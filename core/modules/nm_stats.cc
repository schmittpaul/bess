#include "nm_stats.h"

#include "../utils/ip.h"
#include "../utils/time.h"

// #include <../utils/aho_corasick.h>
#include <../utils/json.h>
// #include <../utils/nm_utils.h>
#include <fstream>

// for convenience
using json = nlohmann::json;

using bess::utils::be32_t;
using bess::utils::NM_Flowcache;
using bess::utils::ToIpv4Address;

const int STATS_OUT_INTERVAL = 5;

double lasttime = get_epoch_time();
NM_Flowcache NMFC;

std::vector<ServiceEntry> service_maps;

CommandResponse nm_stats::Init(const bess::pb::EmptyArg &) {
  task_id_t tid;

  // aho_corasick_tries.push_back(std::make_pair("Youtube",
  // bess::utils::trie())); aho_corasick_tries[0].second.insert("youtube.com");
  // aho_corasick_tries[0].second.insert("ytimg.com");
  // aho_corasick_tries[0].second.insert("googlevideo.com");

  std::ifstream ifs("nmconfig.json");
  json jf;
  ifs >> jf;
  json dnsjson = jf["DNSCache"]["Services"];
  // iterate the array
  for (json::iterator it = dnsjson.begin(); it != dnsjson.end(); ++it) {
    json servicejson = it.value();

    std::string sname = servicejson.value("Name", "error");
    if (sname.compare("error") == 0) {
      continue;
    }

    std::vector<ServiceEntry>::iterator idx =
        std::find_if(service_maps.begin(), service_maps.end(),
                     [&sname](const ServiceEntry &element) {
                       return element.name == sname;
                     });

    if (idx == service_maps.end()) {
      ServiceEntry se = {sname, new bess::utils::trie};
      service_maps.push_back(se);
      // printf("INSERTING %s \n", sname.c_str());
    }

    std::vector<ServiceEntry>::iterator idx2 =
        std::find_if(service_maps.begin(), service_maps.end(),
                     [&sname](const ServiceEntry &element) {
                       return element.name == sname;
                     });

    if (idx2 == service_maps.end()) {
      continue;
    }

    for (const auto &element : servicejson["DomainsString"]) {
      std::string domain = element;

      idx2->aho_corasick_map->insert(element);
      // printf("SNAME %s %s\n", sname.c_str(), domain.c_str());
    }

    // for (json::iterator it2 = servicejson.begin(); it2 !=
    servicejson.end();
    //      ++it2) {

    //   printf("JSON %s :: %s \n", it2.key().c_str(),
    //   it2.value().dump().c_str());
    // }

    // printf("JSON: %s \n", it.key().c_str());//,
    // it.value().dump().c_str();
  }

  // for (auto t = service_maps.begin(); t != service_maps.end(); ++t)
  //   printf("TRIED %s %zu\n", t->name.c_str(),
  //          t->aho_corasick_map->parse_text("i1.ytimg.com").size());

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

    // for (auto ii = NMFC.flowServiceMap.begin(); ii != NMFC.flowServiceMap.end();
    //      ii++)
    //   printf("SERVICES: %s %s %d %d %s\n",
    //          ToIpv4Address(be32_t(ii->first.client_ip)).c_str(),
    //          ToIpv4Address(be32_t(ii->first.server_ip)).c_str(),
    //          ii->first.client_port, ii->first.server_port,
    //          ii->second->serverName.c_str());
    printf("*********************************\n");
  }

  return {.block = false, .packets = 0, .bits = 0};
}

ADD_MODULE(nm_stats, "nm_stats",
           "Implements netmicroscope code to print stream statistics")