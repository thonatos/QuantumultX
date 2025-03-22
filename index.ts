import fs from 'fs';
import path from 'path';
import { ProxyAgent, request } from 'urllib';

const HTTP_PROXY = process.env.HTTP_PROXY;

const RULE_SET = [
  // geo-lite
  {
    "type": "remote",
    "tag": "geoip_private",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/private.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_private",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/private.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geoip_cn",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/cn.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_cn",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/cn.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geoip_apple",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/apple.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_apple",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/apple.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_github",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/github.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_youtube",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/youtube.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geoip_telegram",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/telegram.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_telegram",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/telegram.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geoip_twitter",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/twitter.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_twitter",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/twitter.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geoip_cloudflare",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/cloudflare.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_cloudflare",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/cloudflare.json",
    "download_detour": "auto-out"
  },
  // geo
  {
    "type": "remote",
    "tag": "geosite_binance",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/binance.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite_bybit",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/bybit.json",
    "download_detour": "auto-out"
  },
];

const RULE_TYPE_MAP = {
  'ip_cidr': 'ip-cidr',
  'domain': 'host',
  // 'domain_regex': 'host-wildcard',
  'domain_suffix': 'host-suffix',
  'domain_keyword': 'host-keyword',
};

const ruleTypes = new Set();

const proxyAgent = HTTP_PROXY ? new ProxyAgent(HTTP_PROXY) : undefined;

const saveFile = (dir: string, name: string, data: string) => {
  const fileDir = path.resolve(__dirname, dir);
  const filePath = path.join(fileDir, name);
  fs.writeFileSync(filePath, data);
};

const parseRule = (name: string, type: string, rules: string | string[]) => {
  if (!rules) {
    return [];
  }

  const ruleList = Array.isArray(rules) ? rules : [rules];
  return ruleList.map(rule => {
    let _type = type;
    // ipv6
    if(rule.includes(':')) {
      _type = 'ip6-cidr';
    }

    return `${_type}, ${rule}, ${name}`;
  });
};

const transformRuleSet = async (tag: string, url: string) => {
  // download singbox rules
  const { data } = await request(url, {
    followRedirect: true,
    dispatcher: proxyAgent,
    timeout: 30000,
    dataType: 'json',
  });

  const singboxData = JSON.stringify(data, null, 2);
  saveFile('rules-singbox', `${tag}.json`, singboxData);

  // transform rules
  const { version, rules } = data;

  if (version !== 1) {
    return;
  }

  const newRules: string[] = [];

  rules.map((item: any) => {
    Object.keys(item).forEach((key) => {
      if (!ruleTypes.has(key)) {
        ruleTypes.add(key);
      }
    });

    Object.entries(RULE_TYPE_MAP).map(([sourceType, targetType]) => {
      if (!item[sourceType]) {
        return;
      }
      const foramtedRule = parseRule(tag, targetType, item[sourceType]);   
      newRules.push(...foramtedRule);
    });
  });

  // save qx rules
  const qxData = newRules.join('\n');
  saveFile('rules-qx', `${tag}.list`, qxData);
};

const main = async () => {
  const ruleSetList = RULE_SET.filter((item) => item.type === 'remote')

  await Promise.all(
    ruleSetList.map(
      async (ruleSet) => {
        const { url, tag } = ruleSet;

        if (!url) {
          console.log(`URL is empty, skip download`);
          return;
        }

        try {
          console.log('Downloading', tag, url);
          await transformRuleSet(tag, url);
        } catch (error) {
          console.log(`Error downloading ${tag}: ${error}`);
        }
      }
    )
  );

  console.log('rule types', ruleTypes.values());
}

main();
