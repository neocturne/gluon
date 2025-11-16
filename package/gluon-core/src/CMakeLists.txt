cmake_minimum_required(VERSION 3.18)

project(gluon-core C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(-Wall)

add_library(site MODULE site.c)
set_property(TARGET site PROPERTY PREFIX "")
target_link_libraries(site gluonutil lua lua-jsonc)

install(TARGETS site
  LIBRARY DESTINATION lib/lua/gluon
)
