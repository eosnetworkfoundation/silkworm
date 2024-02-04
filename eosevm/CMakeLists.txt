
find_package(Microsoft.GSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(tl-expected REQUIRED)

if(MSVC)
  add_compile_options(/EHsc)
else()
  add_compile_options(-fno-exceptions)
endif()

file(
  GLOB_RECURSE
  EOS_EVM_SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.hpp"
  "*.c"
  "*.h"
)
list(FILTER EOS_EVM_SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER EOS_EVM_SRC EXCLUDE REGEX "_benchmark\\.cpp$")

add_library(eos_evm ${EOS_EVM_SRC})
target_include_directories(eos_evm PUBLIC ${SILKWORM_MAIN_DIR})

set(EOS_EVM_PUBLIC_LIBS
    intx::intx
    nlohmann_json::nlohmann_json
)

target_link_libraries(
  eos_evm
  PUBLIC ${EOS_EVM_PUBLIC_LIBS}
)
