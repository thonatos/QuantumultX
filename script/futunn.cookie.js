const cookieName = 'FUTUNN'
const cookieKey = 'qx_cookie_futunn'
const cookieVal = $request.headers['Cookie']

if (cookieVal) {
  let cookie = $prefs.setValueForKey(cookieVal, cookieKey);
  if (cookie) {
    let msg = `${cookieName}`;
    $notify(msg, 'Cookie写入成功', '详见日志');
    console.log(msg);
    console.log(cookieVal);
  }
}

$done({});
