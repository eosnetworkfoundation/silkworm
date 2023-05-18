/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <silkworm/node/common/settings.hpp>

namespace silkworm::cmd::common {

//! \brief Ensure database is ready to take off and consistent with command line arguments
void run_db_checklist(NodeSettings& node_settings, bool init_if_empty = true);

}  // namespace silkworm::cmd::common