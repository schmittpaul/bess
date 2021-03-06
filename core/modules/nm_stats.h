// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_MODULES_NM_STATS_H_
#define BESS_MODULES_NM_STATS_H_

#include "../module.h"
#include "../utils/nm_cache.h"
#include <../utils/nm_utils.h>

using bess::utils::NM_Flowcache;
using bess::utils::ServiceEntry;

// The NM flowcache is shared amongst all workers to update flows
extern NM_Flowcache NMFC;

// Services map holds ServiceEntry structs that include Aho Corasick tries for
// each service we are interested in
extern std::vector<ServiceEntry> services_map;

class nm_stats final : public Module {
 public:
  nm_stats() : Module() { is_task_ = true; };
  CommandResponse Init(const bess::pb::EmptyArg &arg);

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch,
                             void *arg) override;
};

#endif  // BESS_MODULES_NM_STATS_H_