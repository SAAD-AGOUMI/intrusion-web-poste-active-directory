# Anatomie d'une intrusion : du brute force SSH à la cartographie d'un Active Directory

## Le contexte

**Solvane Biotech** est une entreprise de biotechnologie de taille moyenne, spécialisée dans la thérapie génique. Elle vient d'entrer en phase II d'essais cliniques : ses données de recherche valent cher, et elle attire autant les concurrents que les groupes étatiques.

Elle fait surveiller son réseau 24h/24 par un prestataire de sécurité managée (MSSP). Ce prestataire collecte les logs, génère des alertes et fait un premier tri, mais **il ne fait pas de réponse à incident**. Quand plusieurs alertes remontent le 13 juillet 2025 (brute force sur le serveur web, exécution de PowerShell, trafic sortant inhabituel, signes de vol d'identifiants), c'est à moi, dans le rôle du cabinet de réponse à incident, de reprendre le dossier.

> Il s'agit d'un exercice : un scénario réaliste monté pour s'entraîner, avec de vraies sources (logs, captures réseau, artefacts forensiques), mais pas un client réel. J'ai anonymisé les noms de l'entreprise, du domaine, des machines et des comptes.

## La mission

Trois questions :

1. **Que s'est-il passé ?** Valider les alertes, retrouver l'accès initial et reconstituer la chronologie.
2. **Jusqu'où l'attaquant est-il allé ?** Systèmes touchés, comptes compromis, données qui ont bougé.
3. **Que faire maintenant ?** Contenir, éradiquer, éviter que ça recommence.

Le périmètre : un serveur web exposé sur Internet (`web-srv01`), un poste de recherche (`rsch-ws01`), un serveur de fichiers (`file-srv01`) et un contrôleur de domaine (`dc01`), sur une fenêtre de 7 heures (13 juillet 2025, 20:00 UTC, au 14 juillet, 03:00 UTC).

Je n'ai pas accès à l'infrastructure : seulement un SIEM rempli de logs, des exports `.evtx`, des captures réseau (PCAP) et des artefacts KAPE. Outils : SIEM, Wireshark, EvtxECmd, Timeline Explorer, CyberChef, olevba, PEStudio, PowerShell.

## En bref

- **Accès initial** : brute force SSH sur le serveur web, depuis une seule adresse (`18.212.186.186`).
- **Sur le serveur web** : passage en `root`, création d'un compte, installation d'un **rootkit Apache**.
- **Deuxième front** : un document Word piégé (macro VBA) envoyé à un chercheur, qui télécharge un loader depuis **la même adresse**.
- **Sur le poste** : élévation en SYSTEM, vol d'identifiants avec Mimikatz, cartographie de l'Active Directory, persistance par un service.
- **Sortie des données** : une archive `ad.7z` envoyée par FTP vers le serveur web.

---

## Ma façon de travailler

Dans un SIEM, il y a des millions d'événements et presque tous sont normaux. Je ne cherche donc pas « ce qui est mal » au hasard : je cherche **ce qui n'a pas sa place**, puis je vérifie chaque indice avec une deuxième source.

À chaque trouvaille, je me pose trois questions :

1. Est-ce une preuve, ou du bruit légitime qui y ressemble ?
2. Si j'étais l'attaquant, où aurais-je laissé une autre trace ?
3. Cette trace existe-t-elle dans une source indépendante ?

La deuxième question me fait passer à l'étape suivante. La troisième transforme un indice en conclusion.

Deux réflexes pour tout le dossier :

- Je travaille **en UTC** partout (SIEM, Wireshark, Timeline Explorer). Une heure de décalage suffit à ruiner une chronologie.
- Je ne me contente pas du SIEM. Certaines données n'y sont que partiellement collectées, alors je vais lire les fichiers sources (`.evtx`, PCAP, artefacts).

---

## 1. Le serveur web : on frappe à toutes les portes

Je commence par les accès Apache, en écartant ce qui ressemble à du trafic normal. Trois comportements ressortent, chacun avec son **User-Agent** :

- un outil de découverte de chemins, `gobuster`, à partir de **20:10:59** ;
- des scripts d'un scanner de ports (Nmap NSE) vers **20:19**, avec une rafale de 404 ;
- quelques requêtes manuelles avec un navigateur, pour regarder le contenu.

Petite leçon : je n'avais pas trouvé `gobuster` en cherchant son nom, parce que je ne le connaissais pas à l'avance. Je l'ai trouvé en **excluant** les User-Agents connus et en regardant ce qui restait.

À ce stade, c'est de la reconnaissance. Personne n'est encore entré.

## 2. L'entrée : un brute force SSH

Je passe aux logs d'authentification. Le SIEM n'a pas de commande de comptage à la manière de Splunk, donc je construis un tableau (*Data Table*) avec le compte visé, l'IP source et l'identifiant de règle.

Les règles qui comptent pour SSH : 5760 (échec d'authentification), 5710 (utilisateur inexistant), 5758 (trop de tentatives), 5763 (brute force détecté) et 5715 (succès). Les règles génériques PAM et syslog ne sont pas propres à SSH, donc je les laisse de côté.

Ce que je constate :

- **une seule adresse source**, `18.212.186.186`, dans une plage Amazon (Ashburn, États-Unis, vérifié avec `whois`) ;
- des dizaines d'échecs entre **20:38 et 20:43**, sur `sysadmin` et sur `root` ;
- un **premier succès sur `sysadmin` à 20:48:06**.

## 3. À l'intérieur du serveur : reconnaissance, puis `root`

Une fois connecté, l'attaquant fait ce que ferait n'importe qui : il regarde où il est. Dans l'historique des commandes :

```
hostname
whoami
cat /etc/passwd
```

Puis il copie `/etc/shadow` vers `/tmp/shdw.txt` (les condensats de mots de passe, **T1003.008**) et lance `sudo -l` pour voir ses droits.

À **21:13:56**, il passe `sudo su` et devient `root` (**T1548.003**).

Un détail m'a fait réfléchir : `sudo su` **n'apparaît pas** dans l'historique de commandes, alors que les autres y sont. La raison est technique : cet historique est écrit par un *hook* du prompt, qui note la commande une fois qu'elle est terminée, et `su` ouvre un shell qui ne « termine » pas. En revanche, le journal `sudo` voit tout (`COMMAND=/usr/bin/su`). Ce que j'en retiens : **un log silencieux ne prouve pas que rien ne s'est passé**. Je vérifie la source qui voit réellement l'action.

## 4. Rester : un compte et un rootkit

Devenu `root`, l'attaquant s'installe durablement :

1. il crée un compte, `webadmin`, ajouté au groupe `sudo` ;
2. il télécharge un rootkit Apache depuis un dépôt public (`github.com/0xfffffffa/apache-rootkit`) ;
3. il compile le module `mod_authg.c` avec `apxs`, l'outil officiel d'Apache pour les modules.

À **23:38:50**, il teste son installation : une requête `GET /rkhandler?c=whoami` renvoie un **200**. En clair, le module a enregistré un *handler* qui exécute la commande passée dans le paramètre `c`. Le choix de `whoami` n'est pas anodin : c'est le test classique pour vérifier que le rootkit répond et avec quels droits.

Plus tard (**01:28:20**), un serveur FTP (`pyftpdlib`) démarre sur cette machine, et l'archive `ad.7z` y arrive. Le serveur web devient un point de collecte (voir la section 9).

---

## 5. L'autre front : un document Word piégé

Pendant que le serveur web est sous contrôle, l'attaquant s'intéresse à un chercheur. Dans la capture réseau du poste, ce filtre Wireshark repère le téléchargement :

```
http.request.uri contains "Response_Plan"
```

(`contains`, parce que je cherche une partie du nom, pas la chaîne exacte.) Il révèle un `GET` d'un fichier `.docm` à **23:49:49**, depuis **`18.212.186.186`**, la même adresse que le brute force. Le nom du fichier imite un document interne : un « plan de réponse ». C'est ce qui le rend crédible.

Dans les logs Sysmon du poste, que je convertis en CSV pour les lire dans Timeline Explorer et en ligne de commande :

```
C:\Tools\EvtxECmd\EvtxECmd.exe -f "C:\Case\evidence\rsch-ws01\Sysmon.evtx" --csv "C:\Case\output" --csvf sysmon.csv
```

on lit la suite :

- **23:49:49** : Chrome écrit le fichier dans `C:\Users\user.rsch\Downloads`. Son flux `Zone.Identifier` indique `ZoneId=3`, donc « vient d'Internet » ;
- **23:50:02** : Word ouvre le document ;
- **23:50:16** : Word lance un `powershell.exe` avec une commande de téléchargement.

Une anecdote qui montre l'intérêt de lire la ligne brute : dans Timeline Explorer, j'avais filtré sur le nom du fichier et obtenu plusieurs « utilisateurs » qui valaient tous le nom du fichier. J'avais simplement regardé la mauvaise colonne. La ligne brute du CSV donne le vrai compte, `CORP\user.rsch` :

```
Select-String -Path "C:\Case\output\sysmon.csv" -Pattern 'Response_Plan' | Select-Object -ExpandProperty Line
```

Sysmon avait d'ailleurs déjà étiqueté la chaîne avec MITRE ATT&CK : `T1189` (téléchargement depuis Internet), `T1204` (exécution par l'utilisateur) et `T1137` (Word qui lance un processus enfant).

## 6. Dans la macro

J'exporte le document depuis la capture (*File > Export Objects > HTTP* dans Wireshark) et je l'analyse **sans l'ouvrir** :

```
olevba "C:\Case\export\Solvane_Response_Plan.docm"
```

Ce que j'y lis :

- `document_open()` affiche une **fausse erreur** de conversion de version, avec un bouton Réessayer/Annuler. C'est de l'ingénierie sociale : si la victime clique, la macro appelle `Dropper`.
- `AutoOpen()` est **vide**. C'est un leurre, et le vrai point d'entrée est `document_open`.
- `Dropper()` crée un `WScript.Shell` et lance, en fenêtre cachée, `Invoke-WebRequest` vers `http://18.212.186.186:8080/dochelp.exe` (dépôt dans `C:\Users\Public`), puis `Start-Process`.

Le tableau d'analyse d'olevba sépare deux choses que je garde bien distinctes : les **mots-clés suspects** (`Shell`, `Run`, `powershell`, ouverture automatique) et les vrais **IOC**, c'est-à-dire des indicateurs exploitables. Ici, quatre : l'URL, l'adresse IP, `powershell.exe` et `dochelp.exe`.

## 7. Le loader

J'exporte aussi `dochelp.exe` de la capture et je l'ouvre dans PEStudio, **sans l'exécuter** :

- exécutable **64 bits**, avec une seule bibliothèque importée, `KERNEL32.dll` : typique d'un petit *loader* ;
- deux fonctions importées : `VirtualAlloc` (allocation de mémoire, le signal classique d'un loader qui prépare de la place pour du code) et `ExitProcess` ;
- une section marquée *self-modifying* ;
- un horodatage de compilation en **2010**, très antérieur à l'attaque. Je le prends comme **falsifié ou hérité d'un outil de génération**, pas comme une vraie date de création.

Comme je ne l'ai pas exécuté, je ne sais pas ce qu'il charge exactement. Je sais seulement ce qu'il est capable de faire.

---

## 8. Du simple utilisateur aux droits SYSTEM, puis aux identifiants

Avec la session d'un utilisateur ordinaire, l'attaquant veut deux choses : plus de droits, et des identifiants.

- **23:51:11** : `net user` pour lister les comptes locaux.
- **00:14:10** : un **service** `rnvikl` est installé (Event ID 7045). Il s'exécute en SYSTEM et écrit dans un **named pipe** : c'est une technique d'usurpation de jeton (**T1134.001**) pour récupérer des droits SYSTEM.
- **00:25:28** : `mimikatz.exe` (déposé dans `C:\Users\Public`) ouvre un handle sur `lsass.exe` (Sysmon Event ID 10, **T1003.001**) pour extraire des identifiants en mémoire.

Un service au nom aléatoire, créé juste avant une écriture dans un pipe, n'a rien à faire sur un poste de travail.

## 9. Cartographier l'annuaire, puis sortir les résultats

Avec des identifiants valides, l'attaquant cartographie l'Active Directory avec `AdFind.exe` et `PowerView.ps1`. Les résultats finissent dans **12 fichiers `.txt`** dans `C:\Users\Public`, plus un `ftp.txt` qui contient un script FTP.

Pour les compter sans me fier à l'œil, j'extrais les chemins des événements de création de fichier :

```
Select-String -Path "C:\Case\output\sysmon.csv" -Pattern 'C:\\Users\\Public\\[^\\,"]*\.txt' -AllMatches | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value | Sort-Object -Unique
```

Au passage : une recherche équivalente dans le SIEM ne renvoyait rien, parce que la collecte Sysmon y est partielle. Le CSV local, lui, est complet. Quand le SIEM se tait, je passe aux sources.

Les fichiers sont ensuite compressés en `ad.7z` avec `7z.exe`, puis envoyés par **FTP** vers le serveur web (voir la section 4). Je déduis le canal FTP du script `ftp.txt` et du serveur `pyftpdlib`, pas d'une analyse du trafic : je n'ai pas vérifié le contenu du flux dans la capture.

## 10. La persistance sur le poste

À **01:06:06**, un deuxième service apparaît : `wbJlQcNDIgji`, qui lance **`C:\Users\user.rsch\AppData\Local\Temp\p3rsist.exe`**.

Un service légitime pointe vers un binaire signé, dans `System32` ou `Program Files`. Ici, l'exécutable est dans un dossier temporaire modifiable par l'utilisateur : c'est le signe d'une persistance. Sa configuration se trouve sous `HKLM\SYSTEM\CurrentControlSet\Services`.

Au total, **deux services** créés par l'attaquant : `rnvikl` (élévation) et `wbJlQcNDIgji` (persistance).

---

## 11. Ce que j'en retiens

**Côté méthode**

- Une alerte n'est pas une preuve : je lis la ligne brute avant de conclure.
- Un log silencieux ne prouve rien : je cherche la source qui voit vraiment l'action.
- Les heures viennent de la ligne de log, jamais d'une estimation.
- Un mot-clé suspect n'est pas un IOC.
- Je recoupe : même IP pour le brute force et le téléchargement, même commande dans la macro et dans Sysmon.
- Quand le SIEM n'a pas tout, je lis les fichiers sources.

**Côté détection**, une idée par étape :

| Étape | Ce que je surveillerais |
|---|---|
| Scan web | rafales de 404, User-Agents d'outils connus dans les accès Apache |
| Brute force SSH | règles 5760/5763, échecs par source et par compte (surtout `root`) |
| Élévation Linux | `sudo -l` puis `sudo su`, lecture de `/etc/shadow` |
| Persistance Linux | `adduser`, compilation `apxs`, nouveau module Apache |
| Macro | parent `WINWORD.EXE` avec enfant `powershell.exe` (Sysmon 1) |
| Service suspect | Event ID 7045 avec nom aléatoire ou binaire dans `AppData`/`Temp` |
| Vol d'identifiants | Sysmon 10 avec cible `lsass.exe` depuis un processus non système |
| Exfiltration | transfert FTP vers un serveur inhabituel, grosse archive 7z |

---

## 12. Chronologie (UTC, 13 au 14 juillet 2025)

| Heure | Événement | Système |
|---|---|---|
| 20:10:59 | Découverte de chemins (`gobuster`) | serveur web |
| ~20:19 | Scan NSE, rafale de 404 | serveur web |
| 20:38 à 20:43 | Brute force SSH depuis `18.212.186.186` | serveur web |
| 20:48:06 | Première connexion réussie (`sysadmin`) | serveur web |
| ~21:11 | Reconnaissance, copie de `/etc/shadow`, `sudo -l` | serveur web |
| 21:13:56 | `sudo su` : passage en `root` | serveur web |
| 21:13 à 23:38 | Compte `webadmin`, clonage et compilation du rootkit | serveur web |
| 23:38:50 | Test du rootkit (`/rkhandler?c=whoami`, 200) | serveur web |
| 23:49:49 | Téléchargement du `.docm` | poste de recherche |
| 23:50:02 | Word ouvre le document | poste de recherche |
| 23:50:16 | PowerShell télécharge et lance `dochelp.exe` | poste de recherche |
| 23:51:11 | `net user` | poste de recherche |
| 00:14:10 | Service `rnvikl` (SYSTEM, named pipe) | poste de recherche |
| 00:25:28 | `mimikatz.exe` accède à LSASS | poste de recherche |
| Après 00:25 | AdFind et PowerView, 12 fichiers de résultats | poste de recherche |
| 01:06:06 | Service de persistance `wbJlQcNDIgji` | poste de recherche |
| 01:28:20 | Serveur FTP lancé, `ad.7z` déposée | serveur web |

---

## 13. Mon interprétation

Ce qui suit est une lecture, pas un fait prouvé.

**Un seul opérateur, deux fronts.** La même adresse sert au brute force et au téléchargement du document et du loader. Je lis ça comme un attaquant qui travaille en parallèle sur le serveur exposé et sur un utilisateur.

**Deux rôles.** Le serveur web sert de porte d'entrée, puis de point de collecte (FTP). Le poste de recherche sert à voler des identifiants et à cartographier le domaine.

**L'impact.** Une élévation en SYSTEM, des identifiants extraits de la mémoire et un annuaire cartographié. L'archive que j'ai identifiée contient des résultats d'énumération Active Directory, pas des données de recherche. Je ne peux pas affirmer pour autant qu'aucune donnée sensible n'est sortie : je n'ai pas examiné le serveur de fichiers en profondeur.

**L'attribution.** La chaîne « phishing, document Word à macro, exécutable déposé, accès distant » est un mode opératoire très répandu, associé entre autres à des groupes cybercriminels comme TA505. Je le présente comme un **rapprochement de comportements**, pas comme une attribution : aucune preuve technique ne désigne un groupe précis.

**Ce que je n'ai pas fait.**

- Je n'ai pas analysé en détail le trafic du serveur de fichiers ni les logs du contrôleur de domaine : le mouvement latéral n'est donc pas démontré ici.
- Je n'ai pas exécuté `dochelp.exe` ni `p3rsist.exe` : je ne connais pas leur comportement complet.
- Je n'ai pas daté précisément la création du compte `webadmin` ni la compilation du module dans la fenêtre 21:13 à 23:38.

## 14. Ce que je recommanderais

**Contenir**

1. Isoler le serveur web et le poste de recherche du réseau.
2. Bloquer `18.212.186.186` sur le pare-feu et le proxy (SSH, HTTP/HTTPS, 8080, FTP).
3. Réinitialiser les identifiants de tous les comptes vus sur le poste, puisque LSASS a été lu.

**Préserver**

4. Avant de supprimer quoi que ce soit : copie mémoire et disque, et conservation des binaires et des services suspects.

**Éradiquer**

5. Poste : supprimer les services `rnvikl` et `wbJlQcNDIgji` (clés de registre) **et** leurs fichiers (`p3rsist.exe`, `dochelp.exe`, `mimikatz.exe`, les `.txt` d'AD, `ad.7z`).
6. Serveur web : supprimer le module, le compte `webadmin`, le serveur FTP et l'archive, puis **reconstruire** la machine depuis une image saine. Un rootkit Apache ne se nettoie pas à la main.

**Réduire la surface d'attaque**

7. SSH : interdire la connexion directe de `root` (`PermitRootLogin no`) et imposer les clés (`PasswordAuthentication no`). Bloquer une IP ou changer le port ne gêne que cet attaquant-là.
8. Bloquer les macros venant d'Internet et passer PowerShell en mode contraint pour les utilisateurs.
9. Journaliser les créations de services (7045), les accès à LSASS (Sysmon 10) et les compilations `apxs`.