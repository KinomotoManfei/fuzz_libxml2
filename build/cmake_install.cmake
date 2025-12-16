# Install script for directory: /mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/libxml2/libxml" TYPE FILE FILES
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/c14n.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/catalog.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/chvalid.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/debugXML.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/dict.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/encoding.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/entities.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/globals.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/hash.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/HTMLparser.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/HTMLtree.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/list.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/nanoftp.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/nanohttp.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/parser.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/parserInternals.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/pattern.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/relaxng.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/SAX.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/SAX2.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/schemasInternals.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/schematron.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/threads.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/tree.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/uri.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/valid.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xinclude.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xlink.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlIO.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlautomata.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlerror.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlexports.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlmemory.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlmodule.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlreader.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlregexp.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlsave.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlschemas.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlschemastypes.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlstring.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlunicode.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xmlwriter.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xpath.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xpathInternals.h"
    "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/libxml2/include/libxml/xpointer.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/libxml2.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "programs" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmllint" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmllint")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmllint"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/xmllint")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmllint" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmllint")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmllint")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "programs" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmlcatalog" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmlcatalog")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmlcatalog"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/xmlcatalog")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmlcatalog" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmlcatalog")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/xmlcatalog")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2" TYPE FILE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/libxml2-config.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2" TYPE FILE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/libxml2-config-version.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2/libxml2-export.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2/libxml2-export.cmake"
         "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/CMakeFiles/Export/e84b245f3ece1c96ac9ea1f0afd37f4b/libxml2-export.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2/libxml2-export-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2/libxml2-export.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2" TYPE FILE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/CMakeFiles/Export/e84b245f3ece1c96ac9ea1f0afd37f4b/libxml2-export.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^()$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libxml2" TYPE FILE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/CMakeFiles/Export/e84b245f3ece1c96ac9ea1f0afd37f4b/libxml2-export-noconfig.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/libxml2/libxml" TYPE FILE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/libxml/xmlversion.h")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/libxml-2.0.pc")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE PROGRAM FILES "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/xml2-config")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/mnt/c/Users/桂宸健/Desktop/《软件测试实验》大作业/《软件测试实验》大作业/fuzz-libxml2/fuzz-libxml2/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
