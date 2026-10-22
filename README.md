websec-scanner
==============

Petit scanner de sécurité web que j'ai codé en Python pour mon portfolio de
cybersécurité. En gros tu lui donnes l'URL d'un site et il te dit ce qui cloche
dans sa config : en-têtes de sécurité manquants, TLS mal réglé, fichiers
sensibles accessibles alors qu'ils ne devraient pas, etc. Il ne fait que lire
(des requêtes GET), il n'attaque rien.

Je l'ai fait parce que je refaisais tout le temps les mêmes vérifs à la main
(curl -I, aller voir si /.git/ répond, relire la CSP ligne par ligne) et que
j'en avais marre. Maintenant une commande le fait et me sort un rapport.

Une capture du rapport HTML est dans docs/report_screenshot.png.


Ce qu'il regarde
----------------

- Les en-têtes de sécurité : HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy.
- La CSP, un peu plus en détail que juste "elle est là ou pas" : unsafe-inline,
  unsafe-eval, sources en *, default-src ou base-uri qui manquent.
- Les attributs des cookies : Secure, HttpOnly, SameSite.
- Le TLS : date d'expiration du certif, chaîne de confiance, nom d'hôte, et si
  le serveur accepte encore les vieux TLS 1.0 / 1.1.
- robots.txt : les chemins en Disallow qui en disent long sur ce qu'on cherche
  à cacher.
- Les fichiers exposés : /.git/, .env, sauvegardes, wp-config.php et compagnie.
  Avant de crier au loup il regarde d'abord comment le site répond pour une page
  qui n'existe pas (calibration soft-404), sinon on a plein de faux positifs sur
  les sites qui renvoient 200 pour tout.
- Les bannières Server / X-Powered-By qui balancent les numéros de version.

Chaque problème trouvé est rattaché à une catégorie OWASP Top 10 et à un CWE,
avec une petite reco pour corriger.


Installation
------------

    git clone https://github.com/edggaillard-pixel/websec-scanner.git
    cd websec-scanner
    python -m venv .venv
    .venv\Scripts\activate          (Windows)
    source .venv/bin/activate       (Mac / Linux)
    pip install -e .

Il faut Python 3.11 ou plus.

Important : ne lance ça que sur des sites qui t'appartiennent ou pour lesquels
tu as l'autorisation. Scanner un site au hasard sans permission c'est illégal en
France, donc l'outil refuse carrément de démarrer tant que tu ne mets pas
--authorized. C'est fait exprès.


Comment on s'en sert
--------------------

    # la base
    websec-scan https://example.com --authorized

    # sauver les rapports, en français
    websec-scan https://example.com --authorized --json report.json --html report.html --lang fr

    # plusieurs cibles depuis un fichier, sans bourriner
    websec-scan --authorized -f targets.txt --rate-limit 0.5

    # seulement certains contrôles
    websec-scan https://example.com --authorized --only security_headers,csp,tls

    # voir les contrôles dispo
    websec-scan --list-checks

Les codes de sortie servent pour la CI : 0 = risque faible, 1 = moyen, 2 =
élevé, 3 = t'as oublié --authorized.


Tester sans vraie cible
-----------------------

J'ai mis un petit serveur volontairement troué dans examples/ pour voir le
scanner réagir sans toucher à quoi que ce soit qui ne t'appartient pas :

    python examples/vulnerable_server.py --port 8099
    # puis, dans un autre terminal :
    websec-scan http://127.0.0.1:8099 --authorized --html report.html

Il y a aussi un docker-compose.yml pour le lancer contre OWASP Juice Shop si tu
veux un truc plus réaliste. Et des rapports d'exemple dans examples/ (JSON + HTML,
FR et EN) qui viennent d'un vrai run contre le serveur troué.


Le score
--------

Volontairement tout simple, surtout pour pouvoir l'expliquer à l'oral. Chaque
problème a un poids (info 0, faible 3, moyen 8, élevé 20, critique 40). On
additionne, et le total tombe dans Faible / Moyen / Élevé. Le seul truc en plus :
un seul problème critique (un .git exposé par exemple) fait passer tout le site
en Élevé, peu importe le reste. Les seuils sont dans core/scoring.py si tu veux
les bidouiller.


Comment c'est organisé
----------------------

Le cœur (core/) ne connaît rien de la ligne de commande, donc tu peux juste
l'importer dans ton propre code :

    from websec_scanner.core import Scanner, ScanConfig
    from websec_scanner.reporting import render_json

    result = Scanner(ScanConfig(authorized=True)).scan(["https://example.com"])
    print(render_json(result))

Les contrôles sont dans checks/, un fichier par contrôle, et ils s'enregistrent
tout seuls. Du coup en ajouter un c'est vraiment un seul fichier à écrire. Il y a
un petit guide dans docs/EXTENDING.md.


Ce qu'il ne fait pas
--------------------

C'est un scanner de posture / surface d'attaque, pas un outil de pentest. Pas de
crawl, pas de connexion, pas d'injection de payload, donc il ne trouvera pas de
faille SQL ou de XSS. Le résultat c'est une liste de trucs à durcir en priorité,
pas un certificat qui dit que t'es safe.


Pour développer
---------------

    pip install -e ".[dev]"
    pytest -q          (30 tests, tout est simulé, ça tourne hors ligne)
    ruff check src tests

GitHub Actions relance ruff + pytest sur 3.11 et 3.12 à chaque push.


Licence
-------

MIT.

IA
---

L'intelligence artificielle a été utilisée pour concevoir la charte graphique, structurer les rubriques de ce projet, la traduction en anglais et le readme.
