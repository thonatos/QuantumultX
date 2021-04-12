const cookieName = 'V2EX';
const cookieKey = 'qx_cookie_v2ex';
const cookieVal = $prefs.valueForKey(cookieKey)

function sign() {
  let url = {
    url: `https://www.v2ex.com/mission/daily`,
    headers: {
      Cookie: cookieVal
    }
  };

  $httpClient.get(url, (error, response, data) => {
    if (data.indexOf('每日登录奖励已领取') >= 0) {
      let title = `${cookieName}`;
      let subTitle = `签到结果: 签到跳过`;
      let detail = `今天已经签过了`;

      console.log(`${title}, ${subTitle}, ${detail}`);

      $notify.post(title, subTitle, detail);

    } else {
      signMission(data.match(/<input[^>]*\/mission\/daily\/redeem\?once=(\d+)[^>]*>/)[1])
    }

  });

  $done({});
}

function signMission(code) {
  let url = {
    url: `https://www.v2ex.com/mission/daily/redeem?once=${code}`,
    headers: {
      Cookie: cookieVal,
    }
  };

  $httpClient.get(url, (error, response, data) => {

    if (data.indexOf('每日登录奖励已领取') >= 0) {
      let title = `${cookieName}`;
      let subTitle = `签到结果: 签到成功`;
      let detail = ``;
      console.log(`${title}, ${subTitle}, ${detail}`);
      $notify.post(title, subTitle, detail);

    } else {
      let title = `${cookieName}`;
      let subTitle = `签到结果: 签到失败`;
      let detail = `详见日志`;
      console.log(`签到失败: ${cookieName}, error: ${error}, response: ${response}, data: ${data}`);
      $notify.post(title, subTitle, detail);
    }
  })
}

sign({});