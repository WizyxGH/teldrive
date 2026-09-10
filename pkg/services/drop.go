package services

// Depot de fichiers via un lien de partage.
//
// Un dossier partage avec mot de passe peut accepter des depots : le visiteur
// n'a besoin ni de compte teldrive ni de compte Telegram. Le serveur envoie
// les fichiers pour le compte du proprietaire du partage (ses bots, son canal)
// en reutilisant UploadsUpload et FilesCreate.
//
// Le navigateur envoie des tranches HTTP de ChunkSize octets (sous la limite
// des proxys comme Cloudflare) ; le serveur les recolle au fil de l'eau dans
// un io.Pipe pour produire des morceaux Telegram de PartSize octets. Si une
// tranche echoue, le morceau en cours repart de zero.

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
)

//go:embed drop.html
var dropPage []byte

const (
	dropMaxPartSize  = 2000 * 1024 * 1024 // limite Telegram par morceau (multiple de hash.BlockSize)
	dropMaxSessions  = 64
	dropMaxNameRunes = 255
)

// dropPartSize aligne la taille des morceaux sur hash.BlockSize (16 Mio).
// L'empreinte BLAKE3 d'un fichier est calculee bloc par bloc, morceau par
// morceau : elle ne vaut celle du fichier entier que si chaque morceau (sauf
// le dernier) contient un nombre entier de blocs. Sinon les donnees sont
// intactes mais la verification d'integrite echoue au telechargement.
func dropPartSize(configured int64) int64 {
	size := configured / hash.BlockSize * hash.BlockSize
	return min(max(size, hash.BlockSize), dropMaxPartSize)
}

var (
	errDropDisabled   = errors.New("le depot n'est pas autorise sur ce lien")
	errDropNoPassword = errors.New("le depot exige un lien protege par mot de passe")
	errDropNotFolder  = errors.New("le depot n'est possible que sur un dossier partage")
	errDropUnknown    = errors.New("envoi inconnu ou expire")
	errDropIdle       = errors.New("envoi interrompu faute de donnees")
	errDropAborted    = errors.New("envoi annule")
	errDropBusy       = errors.New("trop d'envois en cours, reessayez plus tard")
	errDropBadName    = errors.New("nom de fichier invalide")
	errDropBadSize    = errors.New("taille de fichier invalide")
	errDropNoSession  = errors.New("le proprietaire du partage n'a plus de session active")
	errDropIncomplete = errors.New("tous les morceaux n'ont pas ete recus")
	errDropNotFound   = errors.New("dossier de destination introuvable")
	errDropChannel    = errors.New("les morceaux ont ete envoyes dans des canaux differents")
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

// RegisterDropRoutes ajoute la page /drop/{id} et l'API /api/drop/{id}/...
func RegisterDropRoutes(r chi.Router, a *apiService) {
	if !a.cnf.Drop.Enable {
		return
	}
	d := &dropService{api: a, uploads: map[string]*dropUpload{}}
	go d.janitor()

	r.Get("/drop/{id}", d.page)
	r.Route("/api/drop/{id}", func(r chi.Router) {
		r.Get("/", d.info)
		r.Patch("/", d.settings)
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

// info est public, comme SharesGetById : il ne revele ni contenu ni mot de passe.
func (d *dropService) info(w http.ResponseWriter, r *http.Request) {
	share, err := d.api.shareGetById(chi.URLParam(r, "id"))
	if err != nil {
		dropError(w, err)
		return
	}
	uid, isOwner := d.owner(r)
	dropJSON(w, http.StatusOK, map[string]any{
		"name":        share.Name,
		"folder":      share.Type == api.FileShareInfoTypeFolder,
		"protected":   share.Password != nil,
		"allowUpload": share.AllowUpload,
		"expiresAt":   share.ExpiresAt,
		"isOwner":     isOwner && uid == share.UserId,
		"chunkSize":   d.api.cnf.Drop.ChunkSize,
	})
}

// settings permet au proprietaire, connecte a teldrive, d'ouvrir ou fermer le depot.
func (d *dropService) settings(w http.ResponseWriter, r *http.Request) {
	uid, ok := d.owner(r)
	if !ok {
		dropError(w, &apiError{err: errors.New("connexion requise"), code: http.StatusUnauthorized})
		return
	}
	var body struct {
		AllowUpload bool `json:"allowUpload"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		dropError(w, &apiError{err: err, code: http.StatusBadRequest})
		return
	}
	id := chi.URLParam(r, "id")
	share, err := d.api.shareGetById(id)
	if err != nil {
		dropError(w, err)
		return
	}
	if share.UserId != uid {
		dropError(w, &apiError{err: errors.New("ce partage ne vous appartient pas"), code: http.StatusForbidden})
		return
	}
	if body.AllowUpload {
		if share.Type != api.FileShareInfoTypeFolder {
			dropError(w, &apiError{err: errDropNotFolder, code: http.StatusBadRequest})
			return
		}
		if share.Password == nil {
			dropError(w, &apiError{err: errDropNoPassword, code: http.StatusBadRequest})
			return
		}
	}
	if err := d.api.db.Model(&models.FileShare{}).Where("id = ? AND user_id = ?", id, uid).
		Update("allow_upload", body.AllowUpload).Error; err != nil {
		dropError(w, &apiError{err: err})
		return
	}
	d.api.cache.Delete(r.Context(), cache.KeyShare(id))
	dropJSON(w, http.StatusOK, map[string]any{"allowUpload": body.AllowUpload})
}

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

// chunk recoit une tranche (?offset=N) du morceau {partNo}. Les tranches d'un
// morceau doivent arriver dans l'ordre ; en cas d'ecart, la reponse 409 indique
// ou reprendre.
func (d *dropService) chunk(w http.ResponseWriter, r *http.Request) {
	// Une reponse anticipee (409, 401...) sans lire la tranche pousse le serveur
	// a fermer la connexion : le client, encore en train d'envoyer, recoit une
	// coupure au lieu de la reponse. On consomme donc le reste, dans la limite
	// d'une tranche (au-dela, la requete n'est de toute facon pas legitime).
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
		dropError(w, &apiError{err: errors.New("parametres de tranche invalides"), code: http.StatusBadRequest})
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
		dropError(w, &apiError{err: errors.New("tranche plus grande que le morceau"), code: http.StatusBadRequest})
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

	// Morceau complet : on ferme le flux et on attend l'envoi du message Telegram.
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

// startPart lance l'envoi Telegram du morceau, alimente ensuite tranche par tranche.
// Le contexte ne derive pas de la requete : il doit survivre a la tranche qui l'a demarre.
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

	// FilesCreate ecrase un fichier homonyme : on choisit un nom libre.
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

// abort abandonne un envoi. Les morceaux deja poses restent dans la table uploads
// et sont effaces de Telegram par la tache cleanUploads apres la retention.
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
				continue // une tranche est en cours de reception : l'envoi est actif
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

// share valide le lien pour un depot : existant, non expire, mot de passe fourni
// et correct (via validFileShare), dossier, depot autorise.
func (d *dropService) share(r *http.Request) (*fileShare, error) {
	share, err := d.api.validFileShare(r, chi.URLParam(r, "id"))
	if err != nil {
		return nil, err
	}
	// Le partage est mis en cache sans expiration : on revalide la date ici.
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now().UTC()) {
		return nil, &apiError{err: ErrShareExpired, code: http.StatusNotFound}
	}
	if share.Type != api.FileShareInfoTypeFolder {
		return nil, &apiError{err: errDropNotFolder, code: http.StatusBadRequest}
	}
	if share.Password == nil {
		return nil, &apiError{err: errDropNoPassword, code: http.StatusForbidden}
	}
	if !share.AllowUpload {
		return nil, &apiError{err: errDropDisabled, code: http.StatusForbidden}
	}
	return share, nil
}

// owner identifie un utilisateur teldrive connecte (cookie de l'interface ou Bearer).
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

// ownerClaims reconstitue l'identite du proprietaire a partir de sa derniere
// session, comme le fait la tache de nettoyage.
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

// resolveParent traduit un chemin relatif au dossier partage en identifiant de
// dossier. path.Clean empeche de remonter au-dessus de la racine du partage.
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
		var n int64
		if err := d.api.db.Model(&models.File{}).
			Where("user_id = ? AND parent_id = ? AND name = ? AND status = 'active'", userID, parentID, candidate).
			Count(&n).Error; err != nil {
			return "", &apiError{err: err}
		}
		if n == 0 {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s (%d)%s", base, i, ext)
	}
	return "", &apiError{err: errors.New("trop de fichiers homonymes"), code: http.StatusConflict}
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

// dropResume repond 409 en indiquant au navigateur ou reprendre l'envoi.
func dropResume(w http.ResponseWriter, partNo int, offset int64, cause error) {
	body := map[string]any{"expectedPart": partNo, "expectedOffset": offset}
	if cause != nil {
		body["error"] = cause.Error()
	}
	dropJSON(w, http.StatusConflict, body)
}
