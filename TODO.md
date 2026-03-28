# GoProxy utls Migration - Yapılacaklar Listesi

**Proje Amacı**: crypto/tls → utls (uTLS) migrasyonu
**Başlangıç Tarihi**: 28 Mart 2026
**Status**: Planlama Aşaması ✅

---

## 📋 Faz Özeti

| Faz | Görevler | Durum |
|-----|----------|-------|
| **1. Analiz & Kurulum** | 1-2 | ⬜ Başlanmadı |
| **2. Core Migration** | 3-8 | ⬜ Başlanmadı |
| **3. Testler & Örnekler** | 9-10 | ⬜ Başlanmadı |
| **4. Validasyon** | 11-14 | ⬜ Başlanmadı |
| **5. Dokümantasyon** | 15 | ⬜ Başlanmadı |

---

## 🚀 FAZA 1: ANALIZ & KURULUM

### ✅ Task 1: utls API Uyumluluğu Analizi
- **Durum**: ⬜ Başlanmadı
- **Amaç**: utls ve crypto/tls arasındaki farklılıkları belirle
- **Başlama Şartı**: Hiçbiri
- **Tamamlama Kriteri**:
  - [ ] utls dokumentasyonu oku
  - [ ] API farklılıkları belirle
  - [ ] Uyumluluğu mapping et
  - [ ] Compatibility matrix yaz

**Önemli Sorular**:
- utls'in `tls.Config` ile uyumluluğu nedir?
- `tls.Certificate` yapısı aynı mı?
- Yeni features nelerdir?
- Breaking changes nelerdir?

---

### ✅ Task 2: go.mod'a utls Dependency Ekleme
- **Durum**: ⬜ Başlanmadı
- **Amaç**: utls kütüphanesini projeye ekle
- **Başlama Şartı**: Task 1 tamamlansın
- **Tamamlama Kriteri**:
  - [ ] `github.com/refraction-networking/utls` add et
  - [ ] `go mod tidy` çalıştır
  - [ ] go.sum verify et
  - [ ] Build test yap
- **Dosyalar Değişecek**: 
  - `go.mod`
  - `go.sum`

**Komutlar**:
```bash
go get github.com/refraction-networking/utls
go mod tidy
go build ./...
```

---

## 🔴 FAZA 2: CORE MIGRATION (KRİTİK)

### ✅ Task 3: certs.go - CA Sertifikası Işleme
- **Durum**: ⬜ Başlanmadı
- **Dosya**: `certs.go` (~60 satır)
- **Kritiklik**: 🔴 YÜKSEK
- **Başlama Şartı**: Task 2 tamamlansın
- **Tamamlama Kriteri**:
  - [ ] Importlar güncelle
  - [ ] `GoproxyCa` variable uyumlulaştır
  - [ ] `init()` fonksiyonu güncelle
  - [ ] `tls.X509KeyPair()` → utls equivalenti değiştir
  - [ ] `tls.Config` → utls.Config değiştir
  - [ ] Build et ve test et

**Değişecek Kodlar**:
```go
// Eski
import "crypto/tls"
var GoproxyCa tls.Certificate
GoproxyCa, err = tls.X509KeyPair(CA_CERT, CA_KEY)

// Yeni
import "github.com/refraction-networking/utls"
// utls eşdeğerleri...
```

---

### ✅ Task 4: internal/signer/signer.go - Sertifika İmzalama
- **Durum**: ⬜ Başlanmadı
- **Dosyalar**: 
  - `internal/signer/signer.go` (~120 satır)
  - `internal/signer/counterecryptor.go` (~35 satır)
- **Kritiklik**: 🔴 YÜKSEK
- **Başlama Şartı**: Task 3 tamamlansın
- **Tamamlama Kriteri**:
  - [✅] Import güncelle
  - [✅] `tls.Certificate` parameters güncelle
  - [✅] `SignHost()` fonksiyonu uyumlulaştır
  - [✅] Certificate struct compatibility kontrol et
  - [✅ ] `*tls.Certificate` return types güncelle
  - [ ] Build et ve test et

**Kritik Fonksiyon**:
```go
func SignHost(ca tls.Certificate, hosts []string) (*tls.Certificate, error)
// → 
func SignHost(ca utls.Certificate, hosts []string) (*utls.Certificate, error)
```

---

### ✅ Task 5: https.go - HTTPS Sunucu/İstemci Kurulumu
- **Durum**: ⬜ Başlanmadı
- **Dosya**: `https.go` (~620 satır) - **EN BÜYÜK DOSYA**
- **Kritiklik**: 🔴 YÜKSEK
- **Başlama Şartı**: Task 4 tamamlansın
- **Tamamlama Kriteri**:
  - [✅] Import güncelle
  - [✅] `ConnectAction.TLSConfig` callback return type güncelle
  - [ ] Global constants güncelle (OkConnect, MitmConnect vb.)
  - [✅] `tls.Server()` → `utls.Server()` değiştir
  - [✅] `tls.Client()` → `utls.Client()` değiştir
  - [] Type assertions `*tls.Conn` → `*utls.UConn` güncelle
  - [ ] `handleHttps()` fonksiyonu güncelle
  - [ ] `TLSConfigFromCA()` fonksiyonu güncelle
  - [ ] `initializeTLSconnection()` fonksiyonu güncelle
  - [ ] Build et ve test et

**Kritik Fonksiyonlar**:
```go
// TLSConfigFromCA - Her MITM connection'ında çağrılır
func TLSConfigFromCA(ca *tls.Certificate) func(...) (*tls.Config, error)

// handleHttps - Ana HTTPS handler
func (proxy *ProxyHttpServer) handleHttps(w http.ResponseWriter, r *http.Request)

// initializeTLSconnection - TLS kurulumu
func (proxy *ProxyHttpServer) initializeTLSconnection(
    ctx *ProxyCtx, targetConn net.Conn, tlsConfig *tls.Config, addr string,
) (net.Conn, error)
```

---

### ✅ Task 6: h2.go - HTTP/2 TLS İşlemleri
- **Durum**: ⬜ Başlanmadı
- **Dosya**: `h2.go` (~177 satır)
- **Kritiklik**: 🟡 ORTA
- **Başlama Şartı**: Task 5 tamamlansın
- **Tamamlama Kriteri**:
  - [✅] Import güncelle
  - [✅] `H2Transport.TLSConfig` type güncelle
  - [ ] `RoundTrip()` fonksiyonu güncelle
  - [ ] `tls.Client()` → `utls.Client()` değiştir
  - [ ] Type assertions güncelle
  - [ ] `proxyFrame()` kontrolü (TLS-free, değişmez)
  - [ ] Build et ve test et

**Değişecek Kod**:
```go
// Eski
type H2Transport struct {
    TLSConfig *tls.Config
    ...
}
rawServerTLS = tls.Client(rawServerTLS, r.TLSConfig)
rawTLSConn, ok := rawServerTLS.(*tls.Conn)

// Yeni
type H2Transport struct {
    TLSConfig *utls.Config
    ...
}
rawServerTLS = utls.Client(rawServerTLS, r.TLSConfig)
rawTLSConn, ok := rawServerTLS.(*utls.UConn)
```

---

### ✅ Task 7: transport/transport.go - Transport Katmanı
- **Durum**: ⬜ Başlanmadı
- **Dosya**: `transport/transport.go` (~410 satır)
- **Kritiklik**: 🟡 ORTA
- **Başlama Şartı**: Task 5 tamamlansın
- **Tamamlama Kriteri**:
  - [ ] Import güncelle
  - [ ] `Transport.TLSClientConfig` type güncelle
  - [ ] `getConn()` fonksiyonu güncelle
  - [ ] `tls.Client()` → `utls.Client()` değiştir
  - [ ] Type assertions güncelle
  - [ ] Build et ve test et

---

### ✅ Task 8: ctx.go - Interface Tipleri Güncelleme
- **Durum**: ⬜ Başlanmadı
- **Dosya**: `ctx.go` (~40 satır)
- **Kritiklik**: 🟡 ORTA
- **Başlama Şartı**: Task 3-4 tamamlansın
- **Tamamlama Kriteri**:
  - [ ] Import güncelle
  - [ ] `CertStorage` interface güncelle
  - [ ] `*tls.Certificate` → `*utls.Certificate` değiştir
  - [ ] Build et ve test et

**Interface Değişimi**:
```go
// Eski
type CertStorage interface {
    Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error)
}

// Yeni
type CertStorage interface {
    Fetch(hostname string, gen func() (*utls.Certificate, error)) (*utls.Certificate, error)
}
```

---

## 🧪 FAZA 3: TESTLER & ÖRNEKLER

### ✅ Task 9: proxy_test.go - Test Suite Güncellemesi
- **Durum**: ⬜ Başlanmadı
- **Dosya**: `proxy_test.go` (~850 satır)
- **Kritiklik**: 🟡 ORTA
- **Başlama Şartı**: Task 3-8 tamamlansın
- **Tamamlama Kriteri**:
  - [ ] Import güncelle
  - [ ] `getCert()` fonksiyonu güncelle
  - [ ] `tls.Dialer` → `utls.Dialer` değiştir
  - [ ] `tls.Client()` → `utls.Client()` değiştir
  - [ ] `TestCertStorage` güncelle
  - [ ] Tüm testler geçsin

**Kritik Test Fonksiyonları**:
- `getCert()` - Sertifika extraction
- `TestProxyWithCertStorage()` - Storage testi
- MITM interception testleri

---

### ✅ Task 10: examples/ - Örnek Kodlar Güncellemesi
- **Durum**: ⬜ Başlanmadı
- **Dosyalar**:
  - `examples/customca/main.go`
  - `examples/certstorage/cache.go`
  - Diğer örnek dosyalar
- **Kritiklik**: 🟢 DÜŞÜK
- **Başlama Şartı**: Task 3-8 tamamlansın
- **Tamamlama Kriteri**:
  - [ ] Tüm examples güncelle
  - [ ] Tüm examples build olsun
  - [ ] Tüm examples çalışsın

---

## ✔️ FAZA 4: VALIDASYON

### ✅ Task 11: HTTPS CONNECT Tünelleme Testi
- **Durum**: ⬜ Başlanmadı
- **Amaç**: Temel HTTPS proxy işlevselliğini test et
- **Test Tipi**: Integration Test
- **Başlama Şartı**: Task 5 tamamlansın

**Test Senaryoları**:
- [ ] Basit HTTPS URL açabilme
- [ ] Certificate verification çalışıyor mu
- [ ] CONNECT method çalışıyor mu

---

### ✅ Task 12: Sertifika Interception/İmzalama Testi
- **Durum**: ⬜ Başlanmadı
- **Amaç**: MITM sertifika generation'ı test et
- **Test Tipi**: Integration Test
- **Kritiklik**: 🔴 ÇOK YÜKSEK
- **Başlama Şartı**: Task 4 tamamlansın

**Test Senaryoları**:
- [ ] Fake sertifika generate edilebiliyor mu
- [ ] İmzalama işlemleri doğru mu
- [ ] Certificate storage çalışıyor mu

---

### ✅ Task 13: HTTP/2 Proxying Testi
- **Durum**: ⬜ Başlanmadı
- **Amaç**: HTTP/2 frame relaying'i test et
- **Test Tipi**: Integration Test
- **Başlama Şartı**: Task 6 tamamlansın

**Test Senaryoları**:
- [ ] HTTP/2 connections açılabiliyor mu
- [ ] Frame relaying doğru çalışıyor mu

---

### ✅ Task 14: Performans & Optimizasyon
- **Durum**: ⬜ Başlanmadı
- **Amaç**: utls performans etkisini test et
- **Başlama Şartı**: Task 11-13 tamamlansın

**Metrikler**:
- [ ] Connection kurma süresi
- [ ] Handshake süresi
- [ ] Throughput testi
- [ ] Memory usage

---

## 📚 FAZA 5: DOKÜMANTASYON

### ✅ Task 15: Dokümantasyon Güncellemesi
- **Durum**: ⬜ Başlanmadı
- **Amaç**: Projeyi utls migration'ı hakkında belgelendir
- **Başlama Şartı**: Task 1-14 tamamlansın

**Yapılacaklar**:
- [ ] README.md güncelle
- [ ] utls features'ını belgelendir
- [ ] Migration notes yaz
- [ ] API changes dokumentasyonu

---

## 🔗 Bağımlılık Grafiği

```
Task 1 (Analiz)
    ↓
Task 2 (go.mod)
    ↓
Task 3 (certs.go) ──────────────── TEMEL
    ↓
Task 4 (signer.go) ──────────────── TEMEL
    ↓
Task 5 (https.go) ──────────────── MERKEZ
    ├─→ Task 6 (h2.go)
    ├─→ Task 7 (transport.go)
    └─→ Task 8 (ctx.go)
    
Task 9 (proxy_test.go) ──────────── TESTLER
Task 10 (examples)

Task 11-14 (Validasyon) ────────── DOĞRULAMA
Task 15 (Dokümantasyon) ────────── SON
```

---

## 🎯 Kritik Fonksiyonlar (Priority Sırasıyla)

### TIER 1: Mutlaka Çalışmalı
- [ ] `init()` (certs.go) - CA yükleme
- [ ] `SignHost()` (signer.go) - Sertifika imzalama
- [ ] `TLSConfigFromCA()` (https.go) - TLS config generation
- [ ] `handleHttps()` (https.go) - HTTPS handler

### TIER 2: Önemli
- [ ] `H2Transport.RoundTrip()` (h2.go) - HTTP/2 proxying
- [ ] `Transport.getConn()` (transport.go) - Transport layer
- [ ] `initializeTLSconnection()` (https.go) - Client TLS setup

### TIER 3: Test & Validation
- [ ] `getCert()` (proxy_test.go) - Test helper
- [ ] `Fetch()` (CertStorage interface) - Certificate caching

---

## 📊 Dosya Kompleksitesi

| Dosya | Satırlar | Zor | Kritiklik | EST. Zaman |
|-------|----------|-----|-----------|-----------|
| https.go | 620+ | ⭐⭐⭐⭐⭐ | 🔴 YÜKSEK | 2-3 saat |
| proxy_test.go | 850+ | ⭐⭐⭐⭐ | 🟡 ORTA | 1-2 saat |
| signer.go | 120+ | ⭐⭐⭐ | 🔴 YÜKSEK | 1 saat |
| h2.go | 177+ | ⭐⭐ | 🟡 ORTA | 30 min |
| transport.go | 410+ | ⭐⭐ | 🟡 ORTA | 45 min |
| certs.go | 60+ | ⭐ | 🔴 YÜKSEK | 20 min |
| ctx.go | 40+ | ⭐ | 🟡 ORTA | 10 min |
| examples | ~200+ | ⭐⭐ | 🟢 DÜŞÜK | 30 min |

---

## ✅ Başlama Stratejisi

**Sıra**:
1. Task 1 - utls araştırması (30 min)
2. Task 2 - go.mod güncelleme (10 min)
3. Task 3 - certs.go migration (20 min)
4. Task 4 - signer.go migration (1 saat)
5. Task 5 - https.go migration (2-3 saat) ⭐ KRITIK
6. Task 6 - h2.go migration (30 min)
7. Task 7 - transport.go migration (45 min)
8. Task 8 - ctx.go güncelleme (10 min)
9. Task 9 - proxy_test.go (1-2 saat)
10. Task 10 - examples (30 min)
11. Task 11-14 - Testing (2-3 saat)
12. Task 15 - Documentation (30 min)

**Tahmini Toplam Süre**: 10-13 saat

---

## 📝 Notlar

- Tüm Tasks sırayla yapılmalı, parallelleştirilmemeli
- Her task'tan sonra `go build ./...` çalıştır
- Git commits düzenli olmalı
- Test suite'i sık çalıştır

---

**Son Güncelleme**: 28 Mart 2026
**Durum**: Planlama ✅
