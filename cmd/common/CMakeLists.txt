#[[
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

if(NOT SILKWORM_CORE_ONLY)
  find_package(CLI11 REQUIRED)

  set(COMMON_SRC
      common.cpp
      common.hpp
      ip_endpoint_option.cpp
      ip_endpoint_option.hpp
      shutdown_signal.cpp
      shutdown_signal.hpp
  )
  add_library(cmd_common "${COMMON_SRC}")
  target_link_libraries(cmd_common silkworm-buildinfo CLI11::CLI11 silkworm_infra)

endif()
