# TheendAuth

Plateforme de gestion de licences sécurisées — liaison HWID, revendeurs, protection, loader et tableau de bord intuitif.

**Panel :** [panel.theend.lat](https://panel.theend.lat) &nbsp;|&nbsp; **Base URL API :** `https://api.theend.lat`

---

## Sommaire

- [Vue d'ensemble](#vue-densemble)
- [AES-256-GCM](#aes-256-gcm)
- [Authentification](#authentification)
- [Anti-Replay](#anti-replay)
- [Codes HTTP](#codes-http)
- [Helper Python](#helper-python)
- [Endpoints](#endpoints)
  - [GET /time](#get-time)
  - [POST /verify](#post-verify)
  - [POST /keys/create](#post-keyscreate)
  - [POST /keys/info](#post-keysinfo)
  - [POST /keys/list](#post-keyslist)
  - [POST /keys/extend](#post-keysextend)
  - [POST /keys/ban](#post-keysban)
  - [POST /keys/unban](#post-keysunban)
  - [POST /keys/delete](#post-keysdelete)
  - [POST /hwid/reset](#post-hwidreset)
  - [POST /protect/version](#post-protectversion)
  - [POST /protect/dll-check](#post-protectdll-check)
  - [POST /protect/exe-check](#post-protectexe-check)
  - [POST /loader/download](#post-loaderdownload)
  - [POST /files/dl](#post-filesdl)
  - [POST /rebrand](#post-rebrand)
  - [POST /credits/topup-create](#post-creditstopup-create)

---

## Vue d'ensemble

TheendAuth est une API REST de gestion de licences logicielles. Tous les échanges sont chiffrés avec AES-256-GCM. Le panel complet est accessible sur [panel.theend.lat](https://panel.theend.lat).

---

## AES-256-GCM

Tous les endpoints utilisent AES-256-GCM.

| Élément | Détail |
|---------|--------|
| Clé AES | `SHA-256(app_token)` |
| Requête | `{"t": app_token, "d": base64(nonce + ciphertext)}` |
| Réponse | `{"d": base64(nonce + ciphertext)}` |
| Nonce | 12 bytes aléatoires, préfixés au ciphertext |

---

## Authentification

| Niveau | Endpoints concernés |
|--------|---------------------|
| Sans secret | `/verify`, `/protect/*`, `/loader`, `/files` |
| `secret_token` requis | `/keys/*`, `/hwid/reset` |
| `rebrand_key` | `/rebrand` |

---

## Anti-Replay

| Champ | Règle |
|-------|-------|
| `nonce` | `secrets.token_hex(16)` — unique par requête |
| `ts` | Timestamp Unix dans ±60 s du serveur |
| Nonce réutilisé dans les 5 min | Rejeté automatiquement |

---

## Codes HTTP

| Code | Signification |
|------|---------------|
| `200` / `201` | Succès |
| `400` | Paramètres invalides |
| `403` | Erreur d'authentification |
| `404` | Ressource introuvable |
| `409` | Conflit |
| `429` | Rate limit dépassé — réponse JSON plain, non chiffrée |

---

## Helper Python

```python
import os, json, base64, hashlib, secrets, requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_TOKEN = "your_app_token"
USER_ID   = "your_user_id"
SECRET    = "your_secret_token"
BASE_URL  = "https://api.theend.lat"

def server_ts():
    return requests.get(BASE_URL + "/time").json()["ts"]

def encrypt(payload, app_token):
    key   = hashlib.sha256(app_token.encode()).digest()
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), app_token.encode())
    return {"t": app_token, "d": base64.b64encode(nonce + ct).decode()}

def decrypt(resp, app_token):
    key = hashlib.sha256(app_token.encode()).digest()
    raw = base64.b64decode(resp["d"])
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], app_token.encode()))

def api(endpoint, payload):
    r = requests.post(BASE_URL + endpoint, json=encrypt(payload, APP_TOKEN))
    return decrypt(r.json(), APP_TOKEN)
```

---

## Endpoints

### GET /time

Récupère le timestamp serveur à utiliser dans le champ `ts`.

**Rate limit :** aucun

**Réponse**

```json
{ "ts": 1753910400 }
```

---

### POST /verify

Vérifie une licence. Lie un HWID à la première utilisation. Plus de 3 HWIDs distincts en 1 h → ban automatique.

**Rate limit :** 30/min par IP · 5/min par HWID

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID de l'application |
| `license_key` | string | ✅ | La licence à vérifier |
| `nonce` | string | ✅ | `secrets.token_hex(16)` — unique par requête |
| `hwid` | string | ➖ | Hardware ID — lié à la 1re vérification |
| `ts` | integer | ✅ | Timestamp serveur — récupéré via `GET /time` |

**Exemple Python**

```python
ts = requests.get("https://api.theend.lat/time").json()["ts"]
payload = {
    "user_id":     USER_ID,
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "hwid":        "DESKTOP-ABC123",
    "nonce":       secrets.token_hex(16),
    "ts":          ts,
}
r      = requests.post(BASE_URL + "/verify", json=encrypt(payload, APP_TOKEN))
result = decrypt(r.json(), APP_TOKEN)
```

**Réponse**

```json
{
  "status":      "success",
  "app":         "MyApp",
  "days_left":   30,
  "hwid":        "DESKTOP-ABC123",
  "expires_at":  "2025-08-01 12:00:00",
  "key_by":      "theend",
  "key_aes":     "••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••",
  "rebrand_key": "abc123..."
}
```

---

### POST /keys/create

Crée une ou plusieurs licences.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret de l'application |
| `days` | integer | ✅ | Durée de validité en jours |
| `count` | integer | ➖ | Nombre de licences à créer (défaut : 1) |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{
  "status": "success",
  "keys": ["XXXX-XXXX-XXXX-XXXX", "YYYY-YYYY-YYYY-YYYY"]
}
```

---

### POST /keys/info

Retourne les détails d'une licence.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `license_key` | string | ✅ | La licence à consulter |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{
  "status":     "success",
  "key":        "XXXX-XXXX-XXXX-XXXX",
  "days_left":  15,
  "expires_at": "2025-08-01 12:00:00",
  "hwid":       "DESKTOP-ABC123",
  "banned":     false,
  "created_by": "theend"
}
```

---

### POST /keys/list

Liste les licences avec pagination.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `page` | integer | ➖ | Page (défaut : 1) |
| `per_page` | integer | ➖ | Résultats par page (défaut : 50) |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{
  "status": "success",
  "total":  120,
  "page":   1,
  "keys": [
    { "key": "XXXX-XXXX-XXXX-XXXX", "days_left": 15, "banned": false }
  ]
}
```

---

### POST /keys/extend

Prolonge la durée d'une licence.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `license_key` | string | ✅ | La licence à prolonger |
| `days` | integer | ✅ | Jours à ajouter |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{
  "status":     "success",
  "days_left":  45,
  "expires_at": "2025-09-15 12:00:00"
}
```

---

### POST /keys/ban

Bannit une licence.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `license_key` | string | ✅ | La licence à bannir |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "message": "Key banned." }
```

---

### POST /keys/unban

Débannit une licence.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `license_key` | string | ✅ | La licence à débannir |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "message": "Key unbanned." }
```

---

### POST /keys/delete

Supprime définitivement une licence.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `license_key` | string | ✅ | La licence à supprimer |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "message": "Key deleted." }
```

---

### POST /hwid/reset

Réinitialise le HWID lié à une licence.

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `license_key` | string | ✅ | La licence concernée |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "message": "HWID reset." }
```

---

### POST /protect/version

Vérifie la version courante de l'application protégée.

**Auth :** aucune

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "version": "1.4.2" }
```

---

### POST /protect/dll-check

Vérifie l'intégrité d'une DLL.

**Auth :** aucune

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `dll_name` | string | ✅ | Nom du fichier DLL |
| `hash` | string | ✅ | Hash SHA-256 du fichier local |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "valid": true }
```

---

### POST /protect/exe-check

Vérifie l'intégrité d'un exécutable.

**Auth :** aucune

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `exe_name` | string | ✅ | Nom du fichier EXE |
| `hash` | string | ✅ | Hash SHA-256 du fichier local |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "valid": true }
```

---

### POST /loader/download

Télécharge le loader de l'application (ZIP ou binaire).

**Auth :** aucune

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `license_key` | string | ✅ | Licence valide |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse** : fichier binaire (stream) ou JSON `{ "url": "..." }` selon la configuration.

---

### POST /files/dl

Télécharge un fichier associé à l'application (DLL, ressource, etc.).

**Auth :** aucune

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `license_key` | string | ✅ | Licence valide |
| `file_id` | string | ✅ | Identifiant du fichier |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse** : fichier binaire (stream).

---

### POST /rebrand

Applique un rebrand (logo, nom, couleurs) au loader.

**Auth :** `rebrand_key` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `rebrand_key` | string | ✅ | Clé de rebrand (champ `rebrand_key` retourné par `/verify`) |
| `app_name` | string | ➖ | Nom de l'application |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{ "status": "success", "message": "Rebrand applied." }
```

---

### POST /credits/topup-create

Génère un code de recharge de crédits (usage revendeur).

**Auth :** `secret_token` requis

**Paramètres**

| Champ | Type | Requis | Notes |
|-------|------|--------|-------|
| `user_id` | string | ✅ | Owner ID |
| `secret_token` | string | ✅ | Token secret |
| `amount` | integer | ✅ | Montant de crédits à charger |
| `nonce` | string | ✅ | Unique par requête |
| `ts` | integer | ✅ | Timestamp serveur |

**Réponse**

```json
{
  "status": "success",
  "code":   "TOPUP-XXXX-XXXX-XXXX",
  "amount": 100
}
```

---

## Liens

- **Panel :** [panel.theend.lat](https://panel.theend.lat)
- **Dashboard :** [panel.theend.lat/dashboard](https://panel.theend.lat/dashboard)
- **API Reference :** [panel.theend.lat/api-reference](https://panel.theend.lat/api-reference)
- **Applications :** [panel.theend.lat/apps](https://panel.theend.lat/apps)
- **Fichiers :** [panel.theend.lat/files](https://panel.theend.lat/files)
- **Revendeurs :** [panel.theend.lat/resellers](https://panel.theend.lat/resellers)
- **Top-Up Codes :** [panel.theend.lat/topup](https://panel.theend.lat/topup)
- **Support :** [panel.theend.lat/support](https://panel.theend.lat/support)
- **Rebrands :** [panel.theend.lat/rebrands](https://panel.theend.lat/rebrands)
