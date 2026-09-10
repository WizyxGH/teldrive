package services

// Access to a shared folder through links, read-only or writable.
//
// A folder can have several links, each with its own password, expiry and
// access level: read (browse, download) or write (also upload files, create
// folders, rename). Visitors need neither a teldrive nor a Telegram account:
// the server acts on behalf of the share owner (their bots, their channel) by
// reusing UploadsUpload, FilesCreate and FilesUpdate. The owner manages links
// from /drop/{id}.
//
// The teldrive UI only knows one link per folder: its share dialog edits or
// deletes every link of the folder at once.
//
// The browser sends HTTP chunks of ChunkSize bytes (below proxy limits such as
// Cloudflare's); the server streams them through an io.Pipe into Telegram
// parts of PartSize bytes. If a chunk fails, the current part restarts from
// offset 0.

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tgdrive/teldrive/internal/api"
	"github.com/tgdrive/teldrive/internal/auth"
	"github.com/tgdrive/teldrive/internal/cache"
	"github.com/tgdrive/teldrive/internal/hash"
	"github.com/tgdrive/teldrive/internal/logging"
	"github.com/tgdrive/teldrive/pkg/models"
	"github.com/tgdrive/teldrive/pkg/types"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

//go:embed drop.html
var dropPage []byte

const (
	dropMaxPartSize  = 2000 * 1024 * 1024 // Telegram per-part limit (a multiple of hash.BlockSize)
	dropMaxSessions  = 64
	dropMaxNameRunes = 255
)

// dropPartSize aligns the part size on hash.BlockSize (16 MiB). A file's
// BLAKE3 tree hash is built from per-part block hashes: it only matches the
// hash of the whole file if every part but the last holds a whole number of
// blocks. Otherwise the data is intact but checksum verification fails on
// download.
func dropPartSize(configured int64) int64 {
	size := configured / hash.BlockSize * hash.BlockSize
	return min(max(size, hash.BlockSize), dropMaxPartSize)
}

var (
	errDropReadOnly   = errors.New("this link is read-only")
	errDropNoPassword = errors.New("a writable link must be password-protected")
	errDropNotFolder  = errors.New("write access is only available on a shared folder")
	errDropNotOwner   = errors.New("this share does not belong to you")
	errDropLogin      = errors.New("teldrive login required")
	errDropNoItem     = errors.New("item not found in this folder")
	errDropNameTaken  = errors.New("an item with this name already exists here")
	errDropShortPass  = errors.New("password too short (at least 4 characters)")
	errDropBadExpiry  = errors.New("invalid or past expiry date")
	errDropUnknown    = errors.New("unknown or expired upload")
	errDropIdle       = errors.New("upload aborted: no data received")
	errDropAborted    = errors.New("upload cancelled")
	errDropBusy       = errors.New("too many uploads in progress, try again later")
	errDropBadName    = errors.New("invalid name")
	errDropBadSize    = errors.New("invalid file size")
	errDropNoSession  = errors.New("the share owner no longer has an active session")
	errDropIncomplete = errors.New("not all parts have been received")
	errDropNotFound   = errors.New("destination folder not found")
	errDropChannel    = errors.New("parts were uploaded to different channels")
	errDropBadChunk   = errors.New("invalid chunk parameters")
	errDropBigChunk   = errors.New("chunk larger than the remaining part")
	errDropTooMany    = errors.New("too many items with the same name")
	errDropNoKey      = errors.New("encryption is enabled for links but no encryption key is configured")
)

type dropService struct {
	api     *apiService
	mu      sync.Mutex
	uploads map[string]*dropUpload
}

type dropUpload struct {
	mu        sync.Mutex
	id        string
	shareID   string
	ownerID   int64
	claims    *types.JWTClaims
	name      string
	size      int64
	parentID  string
	mimeType  string
	partSize  int64
	parts     int
	nextPart  int
	channelID int64
	cur       *dropPart
	lastSeen  time.Time
}

type dropPart struct {
	no      int
	size    int64
	written int64
	pw      *io.PipeWriter
	done    chan dropPartResult
	cancel  context.CancelFunc
}

type dropPartResult struct {
	part *api.UploadPart
	err  error
}

// RegisterDropRoutes adds the /drop/{id} page and the /api/drop/{id}/... API.
func RegisterDropRoutes(r chi.Router, a *apiService) {
	if !a.cnf.Drop.Enable {
		return
	}
	d := &dropService{api: a, uploads: map[string]*dropUpload{}}
	go d.janitor()

	r.Get("/drop/{id}", d.page)
	r.Route("/api/drop/{id}", func(r chi.Router) {
		r.Get("/", d.info)
		// owner: links of the folder
		r.Get("/links", d.listLinks)
		r.Post("/links", d.createLink)
		r.Patch("/links/{linkId}", d.updateLink)
		r.Delete("/links/{linkId}", d.deleteLink)
		// visitor holding a writable link
		r.Post("/folders", d.mkdir)
		r.Patch("/items/{itemId}", d.rename)
		r.Post("/uploads", d.begin)
		r.Put("/uploads/{uploadId}/parts/{partNo}", d.chunk)
		r.Post("/uploads/{uploadId}/complete", d.complete)
		r.Delete("/uploads/{uploadId}", d.abort)
	})
}

func (d *dropService) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Write(dropPage)
}

// info is public, like SharesGetById: it reveals neither content nor password.
func (d *dropService) info(w http.ResponseWriter, r *http.Request) {
	share, err := d.api.shareGetById(chi.URLParam(r, "id"))
	if err != nil {
		dropError(w, err)
		return
	}
	uid, isOwner := d.owner(r)
	dropJSON(w, http.StatusOK, map[string]any{
		"name":      share.Name,
		"folder":    share.Type == api.FileShareInfoTypeFolder,
		"protected": share.Password != nil,
		"writable":  share.Writable,
		"expiresAt": share.ExpiresAt,
		"isOwner":   isOwner && uid == share.UserId,
		"chunkSize": d.api.cnf.Drop.ChunkSize,
	})
}

// ---- owner: managing the links of a folder ----

type dropLink struct {
	ID        string     `json:"id"`
	Writable  bool       `json:"writable"`
	Protected bool       `json:"protected"`
	ExpiresAt *time.Time `json:"expiresAt"`
	CreatedAt time.Time  `json:"createdAt"`
}

// ownerShare checks that the request comes from the owner of share {id}.
func (d *dropService) ownerShare(r *http.Request) (*fileShare, error) {
	uid, ok := d.owner(r)
	if !ok {
		return nil, &apiError{err: errDropLogin, code: http.StatusUnauthorized}
	}
	share, err := d.api.shareGetById(chi.URLParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if share.UserId != uid {
		return nil, &apiError{err: errDropNotOwner, code: http.StatusForbidden}
	}
	return share, nil
}

func (d *dropService) listLinks(w http.ResponseWriter, r *http.Request) {
	share, err := d.ownerShare(r)
	if err != nil {
		dropError(w, err)
		return
	}
	var rows []models.FileShare
	if err := d.api.db.Where("file_id = ? AND user_id = ?", share.FileId, share.UserId).
		Order("created_at").Find(&rows).Error; err != nil {
		dropError(w, &apiError{err: err})
		return
	}
	links := make([]dropLink, 0, len(rows))
	for _, s := range rows {
		links = append(links, dropLink{ID: s.ID, Writable: s.Writable, Protected: s.Password != nil,
			ExpiresAt: s.ExpiresAt, CreatedAt: s.CreatedAt})
	}
	dropJSON(w, http.StatusOK, links)
}

type dropLinkReq struct {
	Writable  *bool   `json:"writable"`
	Password  *string `json:"password"`
	ExpiresAt *string `json:"expiresAt"` // RFC 3339; "" removes the expiry
}

func (req *dropLinkReq) hashPassword() (*string, error) {
	if req.Password == nil || *req.Password == "" {
		return nil, nil
	}
	if len([]rune(*req.Password)) < 4 {
		return nil, &apiError{err: errDropShortPass, code: http.StatusBadRequest}
	}
	h, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, &apiError{err: err}
	}
	s := string(h)
	return &s, nil
}

func (req *dropLinkReq) expiry() (*time.Time, error) {
	if req.ExpiresAt == nil || *req.ExpiresAt == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
	if err != nil || t.Before(time.Now()) {
		return nil, &apiError{err: errDropBadExpiry, code: http.StatusBadRequest}
	}
	t = t.UTC()
	return &t, nil
}

func (d *dropService) createLink(w http.ResponseWriter, r *http.Request) {
	share, err := d.ownerShare(r)
	if err != nil {
		dropError(w, err)
		return
	}
	var req dropLinkReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		dropError(w, &apiError{err: err, code: http.StatusBadRequest})
		return
	}
	password, err := req.hashPassword()
	if err != nil {
		dropError(w, err)
		return
	}
	expires, err := req.expiry()
	if err != nil {
		dropError(w, err)
		return
	}
	writable := req.Writable != nil && *req.Writable
	if writable && share.Type != api.FileShareInfoTypeFolder {
		dropError(w, &apiError{err: errDropNotFolder, code: http.StatusBadRequest})
		return
	}
	if writable && password == nil {
		dropError(w, &apiError{err: errDropNoPassword, code: http.StatusBadRequest})
		return
	}
	link := models.FileShare{FileId: share.FileId, UserId: share.UserId, Password: password,
		ExpiresAt: expires, Writable: writable}
	if err := d.api.db.Create(&link).Error; err != nil {
		dropError(w, &apiError{err: err})
		return
	}
	logging.Component("DROP").Info("drop.link_created", zap.String("link_id", link.ID), zap.Bool("writable", writable))
	dropJSON(w, http.StatusCreated, dropLink{ID: link.ID, Writable: writable, Protected: password != nil,
		ExpiresAt: expires, CreatedAt: link.CreatedAt})
}

// updateLink edits a single link (unlike FilesEditShare, which touches every
// link of the folder) and evicts it from the share cache.
func (d *dropService) updateLink(w http.ResponseWriter, r *http.Request) {
	share, err := d.ownerShare(r)
	if err != nil {
		dropError(w, err)
		return
	}
	var req dropLinkReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		dropError(w, &apiError{err: err, code: http.StatusBadRequest})
		return
	}
	linkID := chi.URLParam(r, "linkId")
	var link models.FileShare
	if !isUUID(linkID) || d.api.db.Where("id = ? AND file_id = ? AND user_id = ?", linkID, share.FileId, share.UserId).
		First(&link).Error != nil {
		dropError(w, &apiError{err: ErrShareNotFound, code: http.StatusNotFound})
		return
	}
	updates := map[string]any{}
	if req.Password != nil && *req.Password != "" {
		password, err := req.hashPassword()
		if err != nil {
			dropError(w, err)
			return
		}
		link.Password = password
		updates["password"] = *password
	}
	if req.ExpiresAt != nil {
		expires, err := req.expiry()
		if err != nil {
			dropError(w, err)
			return
		}
		link.ExpiresAt = expires
		updates["expires_at"] = expires
	}
	if req.Writable != nil {
		link.Writable = *req.Writable
		updates["writable"] = *req.Writable
	}
	if link.Writable && share.Type != api.FileShareInfoTypeFolder {
		dropError(w, &apiError{err: errDropNotFolder, code: http.StatusBadRequest})
		return
	}
	if link.Writable && link.Password == nil {
		dropError(w, &apiError{err: errDropNoPassword, code: http.StatusBadRequest})
		return
	}
	if len(updates) > 0 {
		if err := d.api.db.Model(&models.FileShare{}).Where("id = ?", link.ID).Updates(updates).Error; err != nil {
			dropError(w, &apiError{err: err})
			return
		}
		d.api.cache.Delete(r.Context(), cache.KeyShare(link.ID))
	}
	dropJSON(w, http.StatusOK, dropLink{ID: link.ID, Writable: link.Writable, Protected: link.Password != nil,
		ExpiresAt: link.ExpiresAt, CreatedAt: link.CreatedAt})
}

// deleteLink revokes a single link (FilesDeleteShare deletes them all).
func (d *dropService) deleteLink(w http.ResponseWriter, r *http.Request) {
	share, err := d.ownerShare(r)
	if err != nil {
		dropError(w, err)
		return
	}
	linkID := chi.URLParam(r, "linkId")
	if !isUUID(linkID) {
		dropError(w, &apiError{err: ErrShareNotFound, code: http.StatusNotFound})
		return
	}
	res := d.api.db.Where("id = ? AND file_id = ? AND user_id = ?", linkID, share.FileId, share.UserId).
		Delete(&models.FileShare{})
	if res.Error != nil {
		dropError(w, &apiError{err: res.Error})
		return
	}
	if res.RowsAffected == 0 {
		dropError(w, &apiError{err: ErrShareNotFound, code: http.StatusNotFound})
		return
	}
	d.api.cache.Delete(r.Context(), cache.KeyShare(linkID))
	logging.Component("DROP").Info("drop.link_revoked", zap.String("link_id", linkID))
	w.WriteHeader(http.StatusNoContent)
}

// ---- visitor holding a writable link: folders and renaming ----

func (d *dropService) mkdir(w http.ResponseWriter, r *http.Request) {
	share, err := d.share(r)
	if err != nil {
		dropError(w, err)
		return
	}
	var req struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		dropError(w, &apiError{err: err, code: http.StatusBadRequest})
		return
	}
	name, ok := sanitizeDropName(req.Name)
	if !ok {
		dropError(w, &apiError{err: errDropBadName, code: http.StatusBadRequest})
		return
	}
	parentID, err := d.resolveParent(share, req.Path)
	if err != nil {
		dropError(w, err)
		return
	}
	if taken, err := d.nameTaken(share.UserId, parentID, name, ""); err != nil || taken {
		if err == nil {
			err = &apiError{err: errDropNameTaken, code: http.StatusConflict}
		}
		dropError(w, err)
		return
	}
	claims, err := d.ownerClaims(share.UserId)
	if err != nil {
		dropError(w, err)
		return
	}
	folder, err := d.api.FilesCreate(auth.WithClaims(r.Context(), claims), &api.File{
		Name:     name,
		Type:     api.FileTypeFolder,
		ParentId: api.NewOptString(parentID),
	})
	if err != nil {
		dropError(w, err)
		return
	}
	logging.Component("DROP").Info("drop.mkdir", zap.String("share_id", share.ID), zap.String("name", name))
	dropJSON(w, http.StatusCreated, map[string]any{"id": folder.ID.Value, "name": name})
}

func (d *dropService) rename(w http.ResponseWriter, r *http.Request) {
	share, err := d.share(r)
	if err != nil {
		dropError(w, err)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		dropError(w, &apiError{err: err, code: http.StatusBadRequest})
		return
	}
	name, ok := sanitizeDropName(req.Name)
	if !ok {
		dropError(w, &apiError{err: errDropBadName, code: http.StatusBadRequest})
		return
	}
	// Only items inside the shared folder: neither the share root nor anything
	// outside it (FilesUpdate performs no such check).
	itemID := chi.URLParam(r, "itemId")
	inside, err := d.isInShare(itemID, share.FileId, share.UserId)
	if err != nil || !inside {
		dropError(w, &apiError{err: errDropNoItem, code: http.StatusNotFound})
		return
	}
	var item models.File
	if err := d.api.db.Where("id = ? AND user_id = ? AND status = 'active'", itemID, share.UserId).
		First(&item).Error; err != nil || item.ParentId == nil {
		dropError(w, &apiError{err: errDropNoItem, code: http.StatusNotFound})
		return
	}
	if item.Name == name {
		dropJSON(w, http.StatusOK, map[string]any{"id": itemID, "name": name})
		return
	}
	if taken, err := d.nameTaken(share.UserId, *item.ParentId, name, itemID); err != nil || taken {
		if err == nil {
			err = &apiError{err: errDropNameTaken, code: http.StatusConflict}
		}
		dropError(w, err)
		return
	}
	claims, err := d.ownerClaims(share.UserId)
	if err != nil {
		dropError(w, err)
		return
	}
	if _, err := d.api.FilesUpdate(auth.WithClaims(r.Context(), claims),
		&api.FileUpdate{Name: api.NewOptString(name)}, api.FilesUpdateParams{ID: itemID}); err != nil {
		dropError(w, err)
		return
	}
	logging.Component("DROP").Info("drop.rename", zap.String("share_id", share.ID),
		zap.String("from", item.Name), zap.String("to", name))
	dropJSON(w, http.StatusOK, map[string]any{"id": itemID, "name": name})
}

// isInShare reports whether itemID is strictly inside folder rootID.
func (d *dropService) isInShare(itemID, rootID string, userID int64) (bool, error) {
	if !isUUID(itemID) {
		return false, nil
	}
	var inside bool
	err := d.api.db.Raw(`
	WITH RECURSIVE up AS (
		SELECT id, parent_id, 0 AS depth FROM teldrive.files
		WHERE id = ? AND user_id = ? AND status = 'active'
		UNION ALL
		SELECT f.id, f.parent_id, up.depth + 1 FROM teldrive.files f
		JOIN up ON f.id = up.parent_id
		WHERE up.depth < 256
	)
	SELECT EXISTS (SELECT 1 FROM up WHERE parent_id = ?)`, itemID, userID, rootID).Scan(&inside).Error
	return inside, err
}

// nameTaken reports whether an active item already has this name in the folder.
func (d *dropService) nameTaken(userID int64, parentID, name, exceptID string) (bool, error) {
	q := d.api.db.Model(&models.File{}).
		Where("user_id = ? AND parent_id = ? AND name = ? AND status = 'active'", userID, parentID, name)
	if exceptID != "" {
		q = q.Where("id <> ?", exceptID)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return false, &apiError{err: err}
	}
	return n > 0, nil
}

// ---- visitor holding a writable link: uploads ----

func (d *dropService) begin(w http.ResponseWriter, r *http.Request) {
	share, err := d.share(r)
	if err != nil {
		dropError(w, err)
		return
	}
	var req struct {
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Path     string `json:"path"`
		MimeType string `json:"mimeType"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		dropError(w, &apiError{err: err, code: http.StatusBadRequest})
		return
	}
	name, ok := sanitizeDropName(req.Name)
	if !ok {
		dropError(w, &apiError{err: errDropBadName, code: http.StatusBadRequest})
		return
	}
	if req.Size <= 0 {
		dropError(w, &apiError{err: errDropBadSize, code: http.StatusBadRequest})
		return
	}
	if d.api.cnf.Drop.EncryptFiles && d.api.cnf.TG.Uploads.EncryptionKey == "" {
		dropError(w, &apiError{err: errDropNoKey, code: http.StatusServiceUnavailable})
		return
	}
	parentID, err := d.resolveParent(share, req.Path)
	if err != nil {
		dropError(w, err)
		return
	}
	claims, err := d.ownerClaims(share.UserId)
	if err != nil {
		dropError(w, err)
		return
	}

	partSize := dropPartSize(int64(d.api.cnf.Drop.PartSize))
	up := &dropUpload{
		id:       randomDropID(),
		shareID:  share.ID,
		ownerID:  share.UserId,
		claims:   claims,
		name:     name,
		size:     req.Size,
		parentID: parentID,
		mimeType: dropMimeType(name, req.MimeType),
		partSize: partSize,
		parts:    int((req.Size + partSize - 1) / partSize),
		nextPart: 1,
		lastSeen: time.Now(),
	}

	d.mu.Lock()
	if len(d.uploads) >= dropMaxSessions {
		d.mu.Unlock()
		dropError(w, &apiError{err: errDropBusy, code: http.StatusServiceUnavailable})
		return
	}
	d.uploads[up.id] = up
	d.mu.Unlock()

	logging.Component("DROP").Info("drop.begin", zap.String("share_id", share.ID),
		zap.String("file_name", name), zap.Int64("size", req.Size), zap.Int("parts", up.parts))

	dropJSON(w, http.StatusCreated, map[string]any{
		"uploadId":  up.id,
		"parts":     up.parts,
		"partSize":  partSize,
		"chunkSize": d.api.cnf.Drop.ChunkSize,
	})
}

// chunk receives a chunk (?offset=N) of part {partNo}. Chunks of a part must
// arrive in order; on a mismatch, a 409 response tells where to resume.
func (d *dropService) chunk(w http.ResponseWriter, r *http.Request) {
	// Answering early (409, 401...) without reading the chunk makes the server
	// close the connection: the client, still sending, gets a reset instead of
	// the response. Drain the rest, up to one chunk (anything larger is not a
	// legitimate request anyway).
	defer io.CopyN(io.Discard, r.Body, int64(d.api.cnf.Drop.ChunkSize)+1<<20)

	share, err := d.share(r)
	if err != nil {
		dropError(w, err)
		return
	}
	up, err := d.get(chi.URLParam(r, "uploadId"), share.ID)
	if err != nil {
		dropError(w, err)
		return
	}
	partNo, err1 := strconv.Atoi(chi.URLParam(r, "partNo"))
	offset, err2 := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err1 != nil || err2 != nil || r.ContentLength <= 0 {
		dropError(w, &apiError{err: errDropBadChunk, code: http.StatusBadRequest})
		return
	}

	up.mu.Lock()
	defer up.mu.Unlock()
	up.lastSeen = time.Now()

	if up.cur == nil {
		if partNo != up.nextPart || offset != 0 {
			dropResume(w, up.nextPart, 0, nil)
			return
		}
		up.cur = d.startPart(up, partNo)
	}
	part := up.cur
	if partNo != part.no || offset != part.written {
		dropResume(w, part.no, part.written, nil)
		return
	}
	if r.ContentLength > part.size-part.written {
		dropError(w, &apiError{err: errDropBigChunk, code: http.StatusBadRequest})
		return
	}

	n, err := io.Copy(part.pw, io.LimitReader(r.Body, r.ContentLength))
	part.written += n
	up.lastSeen = time.Now()
	if err == nil && n != r.ContentLength {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		d.failPart(up, err)
		dropResume(w, partNo, 0, err)
		return
	}

	if part.written < part.size {
		dropJSON(w, http.StatusOK, map[string]any{"partNo": partNo, "received": part.written, "partDone": false})
		return
	}

	// Part complete: close the stream and wait for the Telegram message.
	part.pw.Close()
	res := <-part.done
	part.cancel()
	up.cur = nil
	if res.err == nil && up.channelID != 0 && res.part.ChannelId != up.channelID {
		res.err = errDropChannel
	}
	if res.err != nil {
		logging.Component("DROP").Error("drop.part_failed", zap.String("upload_id", up.id),
			zap.Int("part_no", partNo), zap.Error(res.err))
		dropResume(w, partNo, 0, res.err)
		return
	}
	up.channelID = res.part.ChannelId
	up.nextPart++
	dropJSON(w, http.StatusOK, map[string]any{"partNo": partNo, "received": part.size, "partDone": true})
}

// startPart starts the Telegram upload of a part, then fed chunk by chunk.
// The context does not derive from the request: it must outlive the chunk
// that started it.
func (d *dropService) startPart(up *dropUpload, partNo int) *dropPart {
	size := up.partSize
	if partNo == up.parts {
		size = up.size - up.partSize*int64(up.parts-1)
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(auth.WithClaims(context.Background(), up.claims))
	part := &dropPart{no: partNo, size: size, pw: pw, done: make(chan dropPartResult, 1), cancel: cancel}

	params := api.UploadsUploadParams{
		ID:            up.id,
		ContentLength: size,
		PartName:      d.partName(up, partNo),
		FileName:      up.name,
		PartNo:        partNo,
		Hashing:       api.NewOptBool(true),
		Encrypted:     api.NewOptBool(d.api.cnf.Drop.EncryptFiles),
	}
	if up.channelID != 0 {
		params.ChannelId = api.NewOptInt64(up.channelID)
	}
	go func() {
		res, err := d.api.UploadsUpload(ctx, &api.UploadsUploadReqWithContentType{
			ContentType: "application/octet-stream",
			Content:     api.UploadsUploadReq{Data: pr},
		}, params)
		if err != nil {
			pr.CloseWithError(err)
		} else {
			pr.Close()
		}
		part.done <- dropPartResult{part: res, err: err}
	}()
	return part
}

func (d *dropService) failPart(up *dropUpload, cause error) {
	if up.cur == nil {
		return
	}
	up.cur.pw.CloseWithError(cause)
	up.cur.cancel()
	up.cur = nil
}

func (d *dropService) complete(w http.ResponseWriter, r *http.Request) {
	share, err := d.share(r)
	if err != nil {
		dropError(w, err)
		return
	}
	up, err := d.get(chi.URLParam(r, "uploadId"), share.ID)
	if err != nil {
		dropError(w, err)
		return
	}
	up.mu.Lock()
	defer up.mu.Unlock()

	var received int64
	d.api.db.Model(&models.Upload{}).Where("upload_id = ?", up.id).Count(&received)
	if up.cur != nil || up.nextPart <= up.parts || received != int64(up.parts) {
		dropError(w, &apiError{err: errDropIncomplete, code: http.StatusConflict})
		return
	}

	// FilesCreate overwrites a file with the same name: pick a free name.
	name, err := d.uniqueName(up.ownerID, up.parentID, up.name)
	if err != nil {
		dropError(w, err)
		return
	}
	file, err := d.api.FilesCreate(auth.WithClaims(r.Context(), up.claims), &api.File{
		Name:      name,
		Type:      api.FileTypeFile,
		ParentId:  api.NewOptString(up.parentID),
		UploadId:  api.NewOptString(up.id),
		ChannelId: api.NewOptInt64(up.channelID),
		Size:      api.NewOptInt64(up.size),
		MimeType:  api.NewOptString(up.mimeType),
		Encrypted: api.NewOptBool(d.api.cnf.Drop.EncryptFiles),
	})
	if err != nil {
		dropError(w, err)
		return
	}
	d.remove(up.id)
	logging.Component("DROP").Info("drop.complete", zap.String("share_id", share.ID),
		zap.String("file_name", name), zap.Int64("size", up.size))
	dropJSON(w, http.StatusCreated, map[string]any{"id": file.ID.Value, "name": name, "size": up.size})
}

// abort drops an upload. Parts already sent stay in the uploads table and are
// removed from Telegram by the cleanUploads job after the retention period.
func (d *dropService) abort(w http.ResponseWriter, r *http.Request) {
	share, err := d.share(r)
	if err != nil {
		dropError(w, err)
		return
	}
	up, err := d.get(chi.URLParam(r, "uploadId"), share.ID)
	if err != nil {
		dropError(w, err)
		return
	}
	up.mu.Lock()
	d.failPart(up, errDropAborted)
	up.mu.Unlock()
	d.remove(up.id)
	w.WriteHeader(http.StatusNoContent)
}

func (d *dropService) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		idle := d.api.cnf.Drop.IdleTimeout
		d.mu.Lock()
		for id, up := range d.uploads {
			if !up.mu.TryLock() {
				continue // a chunk is being received: the upload is active
			}
			if time.Since(up.lastSeen) > idle {
				d.failPart(up, errDropIdle)
				delete(d.uploads, id)
			}
			up.mu.Unlock()
		}
		d.mu.Unlock()
	}
}

// share validates a link for a write operation: exists, not expired, password
// provided and correct (through validFileShare), folder, writable.
func (d *dropService) share(r *http.Request) (*fileShare, error) {
	share, err := d.api.validFileShare(r, chi.URLParam(r, "id"))
	if err != nil {
		return nil, err
	}
	// Shares are cached without TTL: re-check the expiry here.
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now().UTC()) {
		return nil, &apiError{err: ErrShareExpired, code: http.StatusNotFound}
	}
	if share.Type != api.FileShareInfoTypeFolder {
		return nil, &apiError{err: errDropNotFolder, code: http.StatusBadRequest}
	}
	if !share.Writable {
		return nil, &apiError{err: errDropReadOnly, code: http.StatusForbidden}
	}
	// Enforced when a link is made writable; kept here as a safety net.
	if share.Password == nil {
		return nil, &apiError{err: errDropNoPassword, code: http.StatusForbidden}
	}
	return share, nil
}

// owner identifies a logged-in teldrive user (UI cookie or Bearer token).
func (d *dropService) owner(r *http.Request) (int64, bool) {
	token := ""
	if c, err := r.Cookie("access_token"); err == nil {
		token = c.Value
	} else if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimPrefix(h, "Bearer ")
	}
	if token == "" {
		return 0, false
	}
	claims, err := auth.VerifyUser(r.Context(), d.api.db, d.api.cache, d.api.cnf.JWT.Secret, token)
	if err != nil {
		return 0, false
	}
	id, err := strconv.ParseInt(claims.Subject, 10, 64)
	return id, err == nil
}

// ownerClaims rebuilds the owner's identity from their latest session, as the
// cleanup job does.
func (d *dropService) ownerClaims(userID int64) (*types.JWTClaims, error) {
	var s models.Session
	if err := d.api.db.Where("user_id = ?", userID).Order("created_at DESC").First(&s).Error; err != nil {
		return nil, &apiError{err: errDropNoSession, code: http.StatusServiceUnavailable}
	}
	return &types.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: strconv.FormatInt(userID, 10)},
		Hash:             s.Hash,
		TgSession:        s.Session,
	}, nil
}

// resolveParent maps a path relative to the shared folder to a folder ID.
// path.Clean prevents climbing above the root of the share.
func (d *dropService) resolveParent(share *fileShare, rel string) (string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(rel, "\\", "/"))
	if clean == "/" {
		return share.FileId, nil
	}
	id, err := resolvePathID(d.api.db, strings.TrimSuffix(share.Path, "/")+clean, share.UserId)
	if err != nil || id == nil {
		return "", &apiError{err: errDropNotFound, code: http.StatusNotFound}
	}
	var f models.File
	if err := d.api.db.Select("type").Where("id = ? AND user_id = ? AND status = 'active'", *id, share.UserId).
		First(&f).Error; err != nil || f.Type != "folder" {
		return "", &apiError{err: errDropNotFound, code: http.StatusNotFound}
	}
	return *id, nil
}

func (d *dropService) uniqueName(userID int64, parentID, name string) (string, error) {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	candidate := name
	for i := 2; i <= 1000; i++ {
		taken, err := d.nameTaken(userID, parentID, candidate, "")
		if err != nil {
			return "", err
		}
		if !taken {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s (%d)%s", base, i, ext)
	}
	return "", &apiError{err: errDropTooMany, code: http.StatusConflict}
}

func (d *dropService) partName(up *dropUpload, partNo int) string {
	if !d.api.cnf.Drop.ReadablePartNames {
		return randomDropID()
	}
	if up.parts == 1 {
		return up.name
	}
	return fmt.Sprintf("%s.part%03d", up.name, partNo)
}

func (d *dropService) get(id, shareID string) (*dropUpload, error) {
	d.mu.Lock()
	up := d.uploads[id]
	d.mu.Unlock()
	if up == nil || up.shareID != shareID {
		return nil, &apiError{err: errDropUnknown, code: http.StatusNotFound}
	}
	return up, nil
}

func (d *dropService) remove(id string) {
	d.mu.Lock()
	delete(d.uploads, id)
	d.mu.Unlock()
}

func sanitizeDropName(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "", false
	}
	if runes := []rune(name); len(runes) > dropMaxNameRunes {
		name = string(runes[:dropMaxNameRunes])
	}
	return name, true
}

func dropMimeType(name, declared string) string {
	if t := mime.TypeByExtension(strings.ToLower(path.Ext(name))); t != "" {
		return t
	}
	if declared != "" && len(declared) < 128 && !strings.ContainsAny(declared, "\r\n") {
		return declared
	}
	return "application/octet-stream"
}

func randomDropID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func dropJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func dropError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	var ae *apiError
	if errors.As(err, &ae) && ae.code != 0 {
		code = ae.code
	}
	dropJSON(w, code, map[string]any{"error": err.Error()})
}

// dropResume answers 409 and tells the browser where to resume the upload.
func dropResume(w http.ResponseWriter, partNo int, offset int64, cause error) {
	body := map[string]any{"expectedPart": partNo, "expectedOffset": offset}
	if cause != nil {
		body["error"] = cause.Error()
	}
	dropJSON(w, http.StatusConflict, body)
}
