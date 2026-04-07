<!doctype html>
<html lang="en" prefix="og: http://ogp.me/ns#">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="all" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="canonical" href="https://yaraify.abuse.ch/yarahub/" />
    <meta name="description" content="YARA repository">
    <meta name="keywords" content="YARAhub, YARA, repository, hub, repo" />
    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="YARAify - YARAhub">
    <meta name="twitter:description" content="YARA repository">
    <meta name="twitter:url" content="https://yaraify.abuse.ch/yarahub/">
    <meta name="twitter:image" content="https://yaraify.abuse.ch/images/abusech_twitter.png">
    <link rel="icon" href="/favicon.ico">
    <title>YARAify | YARAhub</title>
    <!-- Global site tag (gtag.js) - Google Analytics -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-8KLH71CWS8"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());

      gtag('config', 'G-8KLH71CWS8');
    </script>
    <!-- Bootstrap core CSS -->
    <link href="/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome CSS -->
    <link href="/css/all.min.css" rel="stylesheet">
    <!-- Datatables CSS -->
    <link href="/css/datatables.min.css" rel="stylesheet">
    <!-- Custom styles -->
    <link href="/css/custom.css" rel="stylesheet">
  </head>

  <body>
    <header class="fixed-top">
      <div class="d-flex justify-content-center align-items-center temp-banner">
        <div class="container d-flex justify-content-center align-items-center">
          <p style="margin-bottom: 0 !important; text-align: center">
            <strong>Authenticate for API access</strong> | If you are experiencing issues with receiving data from abuse.ch platforms via API, please ensure your requests are authenticated. ➡️ <a href="https://yaraify.abuse.ch/api/#auth_key" target="_parent">Read here for more info</a>
          </p>
        </div>
      </div>
      <nav class="navbar navbar-expand-md navbar-dark bg-v">
        <div class="container">
          <div class="navbar-header">
            <a class="navbar-brand" href="/">
              <img src="/images/yaraify_logo.svg" alt="YARAify">
            </a>
          </div>
          <ul class="navbar-nav">
            <li class="nav-item">
              <a class="nav-link" href="/scan/" title="Scan a file with YARA"><i class="fas fa-fingerprint"></i> YARA Scan</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="/hunting/" title="Live Hunting Alerts"><i class="far fa-bell"></i> Hunting Alerts</a>
            </li>
            <li class="nav-item dropdown">
              <a class="nav-link dropdown-toggle active" data-bs-toggle="dropdown" href="#" role="button" aria-expanded="false"><i class="fas fa-database"></i> Access Data</a>
              <ul class="dropdown-menu">
                <li><a class="dropdown-item active" href="/yarahub/" title="YARAhub"><i class="fa-solid fa-arrows-to-circle"></i> YARAhub</a></li>
                <li><a class="dropdown-item" href="/api/" title="API"><i class="fa fa-fw fa-code"></i> API</a></li>
                <li><a class="dropdown-item" href="/statistics/" title="Statistics"><i class="fa fa-fw fa-chart-pie"></i> Statistics</a>
              </ul>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="/search/" title="Search the YARAify database"><i class="fa fa-fw fa-search"></i> Search</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="/faq/" title="FAQ"><i class="fas fa-question-circle"></i> FAQ</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="/about/" title="About"><i class="fa fa-fw fa-archway"></i> About</a>
            </li>
            <li class="nav-item">
  <a class="nav-link" href="/login/" title="Login"><i class="fa-solid fa-user"></i> Login</a>
</li>
          </ul>
        </div>
      </nav>
    </header>

    <main class="container-lg">
      <h1 class="mt-5">YARAhub</h1>
      <p>YYARAhub is an initiative of abuse.ch for sharing YARA rules with the community in a structured way. You can download a specific YARA rule or all publicly available rules classified as <kbd>TLP:CLEAR</kbd>.</p>
            <p>You can deploy your own YARA rules after you logged in abuse.ch Authentication Portal <a href="/login/" class="btn btn-xs btn-success" role="button"><i class="fa-solid fa-arrow-right-to-bracket"></i> Login</a></p>
            <a href="/yarahub/yaraify-rules.zip" class="btn btn-primary" role="button"><i class="fa-solid fa-arrow-right-to-bracket"></i> Download all YARA rules</a>
      <table id="yara_rules" class="table table-sm table-hover table-bordered">
        <thead>
         <tr><th>Date added (UTC)</th><th>Rule name</th><th>Author</th><th>Matches</th><th>Last match (UTC)</th></tr>
        </thead>
        <tbody>
        </tbody>
      </table>
    </main>

    <!-- Footer -->
    <footer class="footer">
      <div class="content-container">
        <div class="d-block d-md-flex align-items-center">
          <div class="d-flex gap-4 social-links">
            <a href="https://x.com/abuse_ch" rel="noopener" target="_blank">
              <svg
                height="24"
                width="24"
                fill="white"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 512 512"
              >
                <path
                  d="M389.2 48h70.6L305.6 224.2 487 464H345L233.7 318.6 106.5 464H35.8L200.7 275.5 26.8 48H172.4L272.9 180.9 389.2 48zM364.4 421.8h39.1L151.1 88h-42L364.4 421.8z"
                />
              </svg>
            </a>
            <a
              href="https://www.linkedin.com/company/abuse-ch/"
              rel="noopener"
              target="_blank"
            >
              <svg
                height="24"
                width="24"
                fill="white"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 448 512"
              >
                <path
                  d="M416 32H31.9C14.3 32 0 46.5 0 64.3v383.4C0 465.5 14.3 480 31.9 480H416c17.6 0 32-14.5 32-32.3V64.3c0-17.8-14.4-32.3-32-32.3zM135.4 416H69V202.2h66.5V416zm-33.2-243c-21.3 0-38.5-17.3-38.5-38.5S80.9 96 102.2 96c21.2 0 38.5 17.3 38.5 38.5 0 21.3-17.2 38.5-38.5 38.5zm282.1 243h-66.4V312c0-24.8-.5-56.7-34.5-56.7-34.6 0-39.9 27-39.9 54.9V416h-66.4V202.2h63.7v29.2h.9c8.9-16.8 30.6-34.5 62.9-34.5 67.2 0 79.7 44.3 79.7 101.9V416z"
                />
              </svg>
            </a>
            <a href="https://ioc.exchange/@abuse_ch" rel="noopener" target="_blank">
              <svg
                height="24"
                width="24"
                fill="white"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 448 512"
              >
                <path
                  d="M433 179.1c0-97.2-63.7-125.7-63.7-125.7-62.5-28.7-228.6-28.4-290.5 0 0 0-63.7 28.5-63.7 125.7 0 115.7-6.6 259.4 105.6 289.1 40.5 10.7 75.3 13 103.3 11.4 50.8-2.8 79.3-18.1 79.3-18.1l-1.7-36.9s-36.3 11.4-77.1 10.1c-40.4-1.4-83-4.4-89.6-54a102.5 102.5 0 0 1 -.9-13.9c85.6 20.9 158.7 9.1 178.8 6.7 56.1-6.7 105-41.3 111.2-72.9 9.8-49.8 9-121.5 9-121.5zm-75.1 125.2h-46.6v-114.2c0-49.7-64-51.6-64 6.9v62.5h-46.3V197c0-58.5-64-56.6-64-6.9v114.2H90.2c0-122.1-5.2-147.9 18.4-175 25.9-28.9 79.8-30.8 103.8 6.1l11.6 19.5 11.6-19.5c24.1-37.1 78.1-34.8 103.8-6.1 23.7 27.3 18.4 53 18.4 175z"
                />
              </svg>
            </a>
            <a
              href="https://bsky.app/profile/abuse-ch.bsky.social"
              rel="noopener"
              target="_blank"
            >
              <svg
                height="24"
                width="24"
                fill="white"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 512 512"
              >
                <path
                  d="M111.8 62.2C170.2 105.9 233 194.7 256 242.4c23-47.6 85.8-136.4 144.2-180.2c42.1-31.6 110.3-56 110.3 21.8c0 15.5-8.9 130.5-14.1 149.2C478.2 298 412 314.6 353.1 304.5c102.9 17.5 129.1 75.5 72.5 133.5c-107.4 110.2-154.3-27.6-166.3-62.9l0 0c-1.7-4.9-2.6-7.8-3.3-7.8s-1.6 3-3.3 7.8l0 0c-12 35.3-59 173.1-166.3 62.9c-56.5-58-30.4-116 72.5-133.5C100 314.6 33.8 298 15.7 233.1C10.4 214.4 1.5 99.4 1.5 83.9c0-77.8 68.2-53.4 110.3-21.8z"
                />
              </svg>
            </a>
          </div>
          <div class="footer-policies md:flex-row col">
            <a href="https://abuse.ch/terms-and-conditions/" class="nav-link-w">Terms and Conditions</a>
            <span class="d-md-block d-none">|</span>
            <a href="https://abuse.ch/terms-of-use/" class="nav-link-w">Terms of Use</a>
            <span class="d-md-block d-none">|</span>
            <a href="https://abuse.ch/privacy-policy/" class="nav-link-w">Privacy Policy</a>
            <span class="d-md-block d-none">|</span>
            <a href="https://abuse.ch/cookie-policy/" class="nav-link-w">Cookie Policy</a>
          </div>
        </div>
      </div>
    </footer>

    <!-- Bootstrap core JavaScript
    ================================================== -->
    <script src="/js/jquery-3.6.0.min.js"></script>
    <script src="/js/bootstrap.bundle.min.js"></script>
    <script src="/js/popper.min.js"></script>
    <script src="/js/datatables.min.js"></script>
    <script src="/js/yarahub_55biaoqpsl.js"></script>
    <script src="/js/clipboard.min.js"></script>
    <!-- Initialize ClipboardJS -->
    <script>
      var clipboard = new ClipboardJS('.clipboard');

      clipboard.on('success', function(e) {
        e.clearSelection();
      });
    </script>
 </body>
</html>
