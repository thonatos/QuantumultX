import fs from 'fs';
import path from 'path';
import { ProxyAgent, request } from 'urllib';

const HTTP_PROXY = process.env.HTTP_PROXY;

const RULE_SET = [
  // geo-lite
  {
    "type": "remote",
    "src": "geoip_private",
    "name": "geo_private",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/private.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_private",
    "name": "geo_private",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/private.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geoip_cn",
    "name": "geo_cn",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/cn.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_cn",
    "name": "geo_cn",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/cn.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geoip_apple",
    "name": "geo_apple",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/apple.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_apple",
    "name": "geo_apple",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/apple.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_github",
    "name": "geo_github",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/github.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_youtube",
    "name": "geo_youtube",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/youtube.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geoip_netflix",
    "name": "geo_netflix",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/netflix.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_netflix",
    "name": "geo_netflix",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/netflix.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geoip_telegram",
    "name": "geo_telegram",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/telegram.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_telegram",
    "name": "geo_telegram",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/telegram.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geoip_twitter",
    "name": "geo_twitter",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/twitter.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_twitter",
    "name": "geo_twitter",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/twitter.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geoip_cloudflare",
    "name": "geo_cloudflare",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/cloudflare.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_cloudflare",
    "name": "geo_cloudflare",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/cloudflare.json",
    "download_detour": "auto-out"
  },
  // geo
  {
    "type": "remote",
    "src": "geosite_binance",
    "name": "geo_binance",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/binance.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_bybit",
    "name": "geo_bybit",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/bybit.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "src": "geosite_openai",
    "name": "geo_openai",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/openai.json",
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

const clearRuleDir = (dir: string) => {
  const fileDir = path.resolve(__dirname, dir);

  if (fs.existsSync(fileDir)) {
    const files = fs.readdirSync(fileDir);
    files.forEach(file => {
      if (file.endsWith('.json') || file.endsWith('.list')) {
        fs.unlinkSync(path.join(fileDir, file));
      }
    });
  }
};

const writeRule = (dir: string, name: string, data: string) => {
  const fileDir = path.resolve(__dirname, dir);
  const filePath = path.join(fileDir, name);

  if (!fs.existsSync(fileDir)) {
    fs.writeFileSync(filePath, data);
    return;
  }

  fs.appendFileSync(filePath, data);
};

const parseRule = (name: string, type: string, rules: string | string[]) => {
  if (!rules) {
    return [];
  }

  const ruleList = Array.isArray(rules) ? rules : [rules];
  return ruleList.map(rule => {
    let _type = type;
    // ipv6
    if (type === 'ip-cidr' && rule.includes(':')) {
      _type = 'ip6-cidr';
    }

    return `${_type}, ${rule}, ${name}`;
  });
};

const transformRuleSet = async (src: string, name: string, url: string) => {
  // download singbox rules
  const { data } = await request(url, {
    followRedirect: true,
    dispatcher: proxyAgent,
    timeout: 30000,
    dataType: 'json',
  });

  const singboxData = JSON.stringify(data, null, 2);
  writeRule('rules-singbox', `${src}.json`, singboxData);

  // transform rules
  const { version, rules } = data;

  if (version !== 2) {
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
      const foramtedRule = parseRule(name, targetType, item[sourceType]);
      newRules.push(...foramtedRule);
    });
  });

  console.log(`Transformed ${src} rules:`, newRules.length);
  // save qx rules
  const qxData = newRules.join('\n');
  writeRule('rules-qx', `${name}.list`, qxData + '\n');
};

const main = async () => {
  const ruleSetList = RULE_SET.filter((item) => item.type === 'remote')

  // clear rule dirs
  clearRuleDir('rules-singbox');
  clearRuleDir('rules-qx');

  // download and transform rules
  await Promise.all(
    ruleSetList.map(
      async (ruleSet) => {
        const { url, src, name } = ruleSet;

        if (!url) {
          console.log(`URL is empty, skip download`);
          return;
        }

        try {
          console.log('Downloading', src, url);
          await transformRuleSet(src, name, url);
        } catch (error) {
          console.log(`Error downloading ${src}: ${error}`);
        }
      }
    )
  );

  console.log('rule types', ruleTypes.values());
}

main();
