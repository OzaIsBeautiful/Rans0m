cmake_minimum_required(VERSION 3.10)
project(ransomware_cpp VERSION 1.0)

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
    
    # Optimiser pour la vitesse
    add_compile_options(/O2 /Ot /GL)
endif()

# Trouver OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL introuvable. Spécifiez le chemin avec -DOPENSSL_ROOT_DIR=...")
endif()

# Définir les fichiers sources
set(SOURCES 
    ransomware.cpp
)

# Définir l'exécutable
add_executable(ransomware_cpp ${SOURCES})

# Bibliothèques Windows
if(WIN32)
    set(WINDOWS_LIBS 
        ws2_32      # Winsock
        shlwapi     # Shell API
        shell32     # Shell32
        crypt32     # Cryptographie
        wininet     # Internet
        advapi32    # Services avancés
        user32      # Interface utilisateur
        gdi32       # GDI
        ole32       # OLE
        oleaut32    # OLE Automation
        uuid        # UUID
    )
    target_link_libraries(ransomware_cpp PRIVATE ${WINDOWS_LIBS})
endif()

# Lier OpenSSL
target_include_directories(ransomware_cpp PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ransomware_cpp PRIVATE ${OPENSSL_LIBRARIES})

# Définir les répertoires d'inclusion et de bibliothèques
target_include_directories(ransomware_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Afficher un message d'avertissement
message(WARNING "Ce programme est destiné à des fins éducatives uniquement et ne doit pas être utilisé pour des activités illégales.")

# Installation (option)
install(TARGETS ransomware_cpp DESTINATION bin)

# Messages informatifs
message(STATUS "Configuration terminée pour ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "OpenSSL trouvé: ${OPENSSL_VERSION}") 