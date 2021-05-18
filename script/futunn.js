const cookieName = 'FUTUNN';
const cookieKey = 'qx_cookie_futunn';
const cookieVal = $prefs.valueForKey(cookieKey);

function sign() {
  let url = {
    url: `https://mobile.futunn.com/credits-v2/daily-task`,
    method: 'GET',
    headers: {
      Cookie: cookieVal
    }
  };

  $task.fetch(url).then((response) => {
    // let data = response.body;
    let title = `${cookieName}`;
    let subTitle = `签到结果: 签到成功`;
    let message = `今日签到成功`;

    console.log(`${title}, ${subTitle}, ${message}`);
    $notify(title, subTitle, message);
    $done();
  });
}

sign({});