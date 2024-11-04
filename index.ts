import fs from 'fs';
import path from 'path';
import { ProxyAgent, request } from 'urllib';

const HTTP_PROXY = process.env.HTTP_PROXY;

const RULE_SET = [
  {
    "type": "remote",
    "tag": "geoip-cn",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geoip/cn.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite-cn",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/cn.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite-apple",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/apple.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite-github",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/github.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite-telegram",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/telegram.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite-twitter",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/twitter.json",
    "download_detour": "auto-out"
  },
  {
    "type": "remote",
    "tag": "geosite-cloudflare",
    "format": "source",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo-lite/geosite/cloudflare.json",
    "download_detour": "auto-out"
  }
];

const RULE_TYPE_MAP = {
  'ip_cidr': 'ip-cidr',
  'domain': 'host',
  'domain_suffix': 'host-suffix',
  'domain_keyword': 'host-keyword',
};

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
    return `${type}, ${rule}, ${name}`;
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

        await transformRuleSet(tag, url);
      }
    )
  );
}

main();
