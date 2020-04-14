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

#include "nm_stats.h"

#include "../utils/ip.h"
#include "../utils/time.h"
#include "../port.h"

#include <../utils/json.h>
#include <fstream>

// for convenience
using json = nlohmann::json;

using bess::utils::be32_t;
using bess::utils::ToIpv4Address;

const int STATS_OUT_INTERVAL = 5;

double lasttime = get_epoch_time();
NM_Flowcache NMFC;

std::vector<ServiceEntry> services_map;

CommandResponse nm_stats::Init(const bess::pb::EmptyArg &) {
  task_id_t tid;

  // Read the config json file that contains domains and service names
  std::ifstream ifs("nmconfig.json");
  json jf;
  ifs >> jf;

  // DNSCache Services are the objects that hold domains, regexes, and prefix
  // lists for each service
  json dnsjson = jf["DNSCache"]["Services"];
  // iterate the array
  for (json::iterator it = dnsjson.begin(); it != dnsjson.end(); ++it) {
    json servicejson = it.value();

    // Get the service name, if it fails, continue the loop
    std::string sname = servicejson.value("Name", "error");
    if (sname.compare("error") == 0) {
      continue;
    }

    // Search the services map to see if the service we parse already has a
    // ServiceEntry in the services_map vector
    std::vector<ServiceEntry>::iterator idx =
        std::find_if(services_map.begin(), services_map.end(),
                     [&sname](const ServiceEntry &element) {
                       return element.name == sname;
                     });

    // If the service is new, add a ServiceEntry to the vector
    if (idx == services_map.end()) {
      ServiceEntry se = {sname, new bess::utils::trie};
      services_map.push_back(se);
    }

    // Search the services map to find the appropriate ServiceEntry
    std::vector<ServiceEntry>::iterator idx2 =
        std::find_if(services_map.begin(), services_map.end(),
                     [&sname](const ServiceEntry &element) {
                       return element.name == sname;
                     });

    // Doublecheck to make sure it exists
    if (idx2 == services_map.end()) {
      continue;
    }

    // For each domain in the service json, insert into the Aho Corasick map in
    // the ServiceEntry
    for (const auto &element : servicejson["DomainsString"]) {
      idx2->aho_corasick_map->insert(element);
    }
  }

  tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID)
    return CommandFailure(ENOMEM, "Context creation failed");

  return CommandSuccess();
}

struct task_result nm_stats::RunTask(Context *, bess::PacketBatch *, void *) {
  double now = get_epoch_time();
  double timediff = now - lasttime;
  if (timediff > STATS_OUT_INTERVAL) {
    printf("Timer: %f\n", now);
    lasttime = now;

    // for (auto ii = NMFC.flowcache.begin(); ii != NMFC.flowcache.end(); ii++)
    //   printf("STATS: %s %s %d %d %d\n",
    //          ToIpv4Address(be32_t(ii->first.client_ip)).c_str(),
    //          ToIpv4Address(be32_t(ii->first.server_ip)).c_str(),
    //          ii->first.client_port, ii->first.server_port,
    //          ii->second->fc.clientPackets);
    // printf("*********************************\n");

    for (auto ii = NMFC.flowServiceMap.begin(); ii != NMFC.flowServiceMap.end();
         ii++)
      printf("SERVICES: %s %s %d %d %s\n",
             ToIpv4Address(be32_t(ii->first.client_ip)).c_str(),
             ToIpv4Address(be32_t(ii->first.server_ip)).c_str(),
             ii->first.client_port, ii->first.server_port,
             ii->second->serverName.c_str());
             
    const auto &it = PortBuilder::all_ports();

    for (auto i = it.begin(); i != it.end(); ++i) {
      Port::PortStats stats = i->second->GetPortStats();
      LOG(INFO) << "PACKETS Received: " << stats.inc.packets;
      LOG(INFO) << "PACKETS Dropped: " << stats.inc.dropped;
      LOG(INFO) << "BYTES Received: " << stats.inc.bytes;
    }
    printf("*********************************\n");
  }

  return {.block = false, .packets = 0, .bits = 0};
}

ADD_MODULE(nm_stats, "nm_stats",
           "Implements netmicroscope code to print stream statistics")