# plugin_passwordVerifier_bcrypt CMAKE file

CMAKE_MINIMUM_REQUIRED(VERSION 3.16 FATAL_ERROR)

PROJECT(bcrypt VERSION 1.0 DESCRIPTION "Password Verifier: BCRYPT")

SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCES
  source/plugin_hashScheme_bcrypt.cpp
  )
set(HEADERS
  )
set(INCLUDES
  ${CMAKE_SOURCE_DIR}/msmERP
  ${CMAKE_SOURCE_DIR}/GCL
  )
set(LIBRARIES
  crypt
  )

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE ${INCLUDES}
  )
target_link_libraries(${PROJECT_NAME}
  ${LIBRARIES}
  )
set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".plugin")
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${AUTHPLUGIN_DIR})

