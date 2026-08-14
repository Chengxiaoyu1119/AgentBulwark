(function () {
  if (typeof window === 'undefined') {
    return;
  }

  var bannerPrintedKey = '__chengxiaoyu_console_banner_printed__';
  var originalInfo = console.info;
  console.info = function () {
    var firstArg = arguments.length > 0 ? String(arguments[0]) : '';
    if (firstArg.indexOf('Download the React DevTools') !== -1) {
      return;
    }
    return originalInfo.apply(console, arguments);
  };

  if (window[bannerPrintedKey]) {
    return;
  }
  window[bannerPrintedKey] = true;

  var art = [
    '   ____ _                           _                      ',
    '  / ___| |__   ___ _ __   __ ___  _(_) __ _  ___  _   _ _   _',
    " | |   | '_ \\ / _ \\ '_ \\ / _` \\ \\/ / |/ _` |/ _ \\| | | | | | |",
    ' | |___| | | |  __/ | | | (_| |>  <| | (_| | (_) | |_| | |_| |',
    '  \\____|_| |_|\\___|_| |_|\\__, /_/\\_\\_|\\__,_|\\___/ \\__, |\\__,_|',
    '                         |___/                    |___/        '
  ].join('\n');

  console.log(
    '%c' + art,
    'color:#f59e0b;font-family:Consolas,Menlo,Monaco,monospace;font-size:13px;line-height:1.05;font-weight:700;'
  );
  console.log(
    '%c\u7f51\u5740: https://xa.chengxiaoyu.top\nGithub: https://github.com/Chengxiaoyu1119/agent-security-supervisor',
    'color:#2f81f7;font-family:Consolas,Menlo,Monaco,monospace;font-size:13px;line-height:1.45;font-weight:700;'
  );
})();
