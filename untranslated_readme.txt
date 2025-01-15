Dordea Sabina-Ioana
342C4
							Tema IC

	- implementarile se afla in folderele part1 si part2
	- part1 se ruleaza:
		python skel.py
	- part2 se ruleaza:
		python diff_crypto_attack.py
			--- din folderul sursa part1, respectiv part2
_______________________________________________________________
Part 1


	- In partea 1 a temei, trebuie sa capturam un flag de pe un
server. Pentru a explica atacul, trebuie sa intelegem mai intai
codul care ruleaza pe server.

____________
1. Server-ul si ce ne ajuta din codul lui

- Server-ul are o interfata simplista, cu 3 optiuni:
	1. Get guest token
	2. Login
	3. Exit

- De asemenea, analizand codul server-ului putem afla mai multe
lucruri:
	- GUEST_NAME = b'Anonymous'
	- numele adminului, pe care il vom nota de acum incolo cu
	ADMIN_NAME = b'Ephvuln'
	- nu cunoastem lungimea integritatii
	- un mesaj criptat este format din:
	plain xor rnd + SERVER_PUBLIC_BANNER + integrity,
		unde rnd ramane acelasi pentru fiecare sesiune,
		SERVER_PUBLIC_BANNER este identic mereu si integrity nu
		il cunoastem, dar este folosit ca sa se asigure ca token-ul
		este corect

	mesaj   SERVER_PUBLIC_BANNER    integrity
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │
└────────────────┴────────────────┴────────────────┘

		--- am notat si ne vom referi de acum incolo la plain
		xor rnd ca "mesaj"
		--- am ales sa reprezint un token asa, pentru usurinta
		explicatiei
		--- nu cunosc marimea mesaj, banner, integrity
			- dar stiu ca |mesaj| + |banner| + |integrity| <= 16

	- functia de decrypt a serverului ne ofera mai multe
	informatii, dar cele pe care in final le folosim sunt:
		- atunci cand nu e SERVER_PUBLIC_BANNER, returneaza -1
		- daca integritatea este gresita, returneaza None
	- de asemenea stim ca atunci cand primim un guest token,
	acela foloseste GUEST_NAME ca plain, in functia de encrypt
	- ultimul lucru important este functia de login in sine,
	din care aflam ordinea in care server-ul face verificari,
	fapt pe care il vom exploata mai tarziu:

		1. serverul se asigura ca token-ul este <= cu 16 bytes
			---> daca mesajul rezultat din ADMIN_NAME nu are 16
			bytes, acesta nu necesita padding
		2. serverul verifica daca exista SERVER_PUBLIC_BANNER in
		token
		3. serverul verifica integritatea token-ului
		4. verificari pentru guest token, admin token, sau un
		mesaj incoerent

	Concluzii in urma analizei codului serverului:
		- am mereu acelasi Banner
		- nu e necesar padding-ul
		- cunosc cum trebuie sa arate un token
		- cunosc ordinea in care serverul face verificari

____________
2. Foarte putina teorie si cum imi aflu elementele pentru a
construi un token

	- reiterand, un mesaj arata asa,

	mesaj       SERVER_PUBLIC_BANNER    integrity
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │
└────────────────┴────────────────┴────────────────┘

unde mesaj a fost notat ca plain xor rnd, in cazul nostru
particular, GUEST_NAME xor rnd (preluat din guest token-ul
pe care il primim de la server)

	- de asemenea, eu stiu ca daca vreau sa imi construiesc un
	token de admin, el va trebui sa aiba aceeasi structura:
		ADMIN_NAME xor rnd + SERVER_PUBLIC_BANNER + integrity
	- deoarece am extras de pe server si GUEST_NAME si ADMIN_NAME,
	creearea mesajului a devenit una foarte simpla

vom nota:
GUEST_NAME xor rnd = m1
ADMIN_NAME xor rnd = m2
-----------------------
m1 xor GUEST_NAME = rnd ---> m2 = ADMIN_NAME xor m1 xor GUEST_NAME


	- pentru a afla banner-ul SERVER_PUBLIC_BANNER, ne vom
	folosi de pasii 2 si 3 de verificare al server-ului:

2. serverul verifica daca exista SERVER_PUBLIC_BANNER in token
3. serverul verifica integritatea token-ului

	- de asemenea, vom imparti acest procedeu in doua parti:
		1) aflat inceputul banner-ului
		2) aflat finalul banner-ului

1) inceputul banner-ului

presupunem iar ca tokenul nostru arata asa, nestiind unde exact
este delimitarea intre mesaj, banner si integrity

┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │
└────────────────┴────────────────┴────────────────┘


incepem prin a construi un payload nou dupa regula: inlocuiesc
de la stanga la dreapta cate un byte cu "X" din guest token si
apoi il trimit la server ca login
	--- aici este momentul in care incepem sa exploatam modul de
	verificare al serverului


vom avea niste pasi de aceasta forma:

	"TOKEN" TRIMIS						RASPUNS SERVER
┌────────────────┬────────────────┬────────────────┐
│ X  m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │ -> integritate gresita (natural, deoarece am
└────────────────┴────────────────┴────────────────┘    schimbat mesajul)
┌────────────────┬────────────────┬────────────────┐
│ X  X  m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │ -> integritate gresita
└────────────────┴────────────────┴────────────────┘
┌────────────────┬────────────────┬────────────────┐
│ X  X  X  ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │ -> integritate gresita
└────────────────┴────────────────┴────────────────┘
 .
 .
 .
┌────────────────┬────────────────┬────────────────┐
│ X  X  X  ... X │ b0 b1 b2 ... bn│i0 i1 i2 ... in │ -> integritate gresita
└────────────────┴────────────────┴────────────────┘
┌────────────────┬────────────────┬────────────────┐
│ X  X  X  ... X │ X  b1 b2 ... bn│i0 i1 i2 ... in │ -> lipseste banner-ul ("Wrong server secret")
└────────────────┴────────────────┴────────────────┘

	--- In momentul in care raspunsul de la server se schimba din
	"integritate gresita" in "Wrong server secret", imi dau seama
	ca am suprascris inceputul banner-ului, astfel determinand
	pozitia de inceput a SERVER_PUBLIC_BANNER din token-ul de
	guest primit

2) finalul banner-ului
	- o sa aplicam o metoda similara ca mai sus, dar de data
	aceasta payload-ul va fi de forma: n bytes din guest token
	+ "X" paddind pana la 16 bytes

	"TOKEN" TRIMIS						RASPUNS SERVER
┌────────────────┬────────────────┬────────────────┐
│ m0 X  X  ... X │ X  X  X  ... X │X  X  X  ... X  │ -> lipseste banner-ul ("Wrong server secret")
└────────────────┴────────────────┴────────────────┘
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 X  ... X │ X  X  X  ... X │X  X  X  ... X  │ -> lipseste banner-ul
└────────────────┴────────────────┴────────────────┘
 .
 .
 .
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ X  X  X  ... X │X  X  X  ... X  │ -> lipseste banner-ul
└────────────────┴────────────────┴────────────────┘
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 X  X  ... X │X  X  X  ... X  │ -> lipseste banner-ul
└────────────────┴────────────────┴────────────────┘
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 X  ... X │X  X  X  ... X  │ -> lipseste banner-ul
└────────────────┴────────────────┴────────────────┘
 .
 .
 .
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│X  X  X  ... X  │ -> integritate gresita
└────────────────┴────────────────┴────────────────┘

	--- In momentul in care raspunsul de la server se schimba
	din "Wrong server secret" in "integritate gresita" , imi dau
	seama ca am pus suficienti bytes din token incat sa trimit
	tot banner-ul, astfel determinand pozitia de final a
	SERVER_PUBLIC_BANNER din token-ul de guest primit

---------------------
	- in acest punct, cunoastem mesajul pe care trebuie sa il
	trimitem, cunoastem banner-ul, ne mai trebuie doar integritatea
		- lungimea acesteia se afla dintr-un simplu calcul:
			|guest_token| - final_banner
		- in cazul nostru, ea este de un byte, asa ca, pentru a
		afla integritatea, nu avem decat sa facem brute force pe
		cele 256 de valori pe care le poate avea integritatea,
		fortand sa fie reprezentata pe un singur byte(python mai
		face scheme cu conversiile si iti trece val pe 2 bytes)

____________
3. Implementarea si final:
	Atacul si codul acestuia se rezuma la:
		1. un for pe lungimea guest token
				inlocuiesc bytes din token pana aflu inceputul bannerului
		2. un for pe lungimea guest token
				pun bytes din token si completez pana la 16 bytes
				pana aflu finalul bannerului
		3. un for pentru toate cele 256 de valori ( integrity=0...255)
			pe care le ia integrity
				construiesc token-ul si il trimit la server
				daca am primit CTF-ul de la server, SUCCESS



_______________________________________________________________
Part 2

	- In a 2-a parte a temei, vom incerca un atac differential,
	in care avem primii 8 bytes ai cheii si incercam sa ii aflam
	pe ultimii 4, unde
		k = k1 | k2 | k3,
		k1, k2 cunoscute

	- Atacam un block cipher simplificat, cu o cheie de 96 de biti = 12 bytes
	si mesaje de 64 de biti

                   32 biti            32 biti
            ┌─────────────────┬──────────────────┐
m =         │       L0        │        R0        │
            └───────┬─────────┴─────────────┬────┘
                    │                       │
                    │       ┌──┐            │
                    │       │k1├───►xor◄────┤
                    │       └──┘     │      │
                    ▼             ┌──▼──┐   │
                   xor ◄──────────┤S-box│   │
                    │             └─────┘   │
                    │                       │
                    │  ┌────────────────────┘
                    │  │
                    └──┼───────────────┐
                       │               │
            ┌──────────┴──────┬────────┴─────────┐
            │       L1        │        R1        │
            └───────┬─────────┴─────────────┬────┘
                    │                       │
                    │       ┌──┐            │
                    │       │k2├───►xor◄────┤
                    │       └──┘     │      │
                    ▼             ┌──▼──┐   │
                   xor ◄──────────┤S-box│   │
                    │             └─────┘   │
                    │                       │
                    │  ┌────────────────────┘
                    │  │
           	    └──┼───────────────┐
                       │               │
  	    ┌──────────┴──────┬────────┴─────────┐
            │       L2        │        R2        │
            └───────┬─────────┴─────────────┬────┘
            	    │                       │
            	    X       ┌──┐            │
                    │       │k3├───►xor◄────┤
                    │       └──┘     │      │
                    ▼             ┌──▼──┐   │
                   xor ◄──────────┤S-box│   │
                    │             └─────┘   │
                    │                       │
                    │  ┌────────────────────┘
                    │  │
                    └──┼───────────────┐
                       │               │
            ┌──────────▼──────┬────────▼─────────┐
c = E(k, m) │       L3        │        R3        │
            └─────────────────┴──────────────────┘

--- Punctul de atac fiind, marcat cu X, din a 3-a runda(cea finala)

	     ┌─────────────────┬──────────────────┐
             │       L2        │        R2        │
             └───────┬─────────┴─────────────┬────┘
            	     │                       │
       E' = (k,m) -> X       ┌──┐            │
                     │       │k3├───►xor◄────┤
                     │       └──┘     │      │
                     ▼             ┌──▼──┐   │
                    xor ◄──────────┤S-box│   │
                     │             └─────┘   │
                     │                       │
                     │  ┌────────────────────┘
                     │  │
                     └──┼───────────────┐
                        │               │
             ┌──────────▼──────┬────────▼─────────┐
             │       L3        │        R3        │
             └─────────────────┴──────────────────┘


- vom incepe prin a genera perechi de mesaje (m1, m2), pentru
care avem criptarea primita de la server: (c1, c2)
	--- definim ca pereche de mesaje (m1, m2) mesaje generate
	aleator, cu proprietatea ca:
	R(m1) = R(m2) si
	L(m1) xor L(m2) = deltax, cu deltax cat mai mare

__________o mica paranteza de implementare si deltax___________
	- teoretic, am lua deltax = b'11111111':
		- deoarece vrem sa il comparam cu deltay, care are 8 biti,
		pentru ca este calculat in atacul pe bytes al lui k3,
		unde luam s-box-uri pe rand
		- si ne referim la partea stanga, atunci cand vorbim de
		deltax, unde vrem diferenta, iar partea dreapta poate sa
		fie generata separat si lipita la partea stanga a fiecarui
		mesaj, deoarece ea este comuna
	- totusi, in cazul in care am generat un m = b'00001...',
	python o sa ne faca o conversie si o sa ne intoarca 7 bytes, nu 8,
	si o sa ne strice calculele (totusi, am pastrat verificarea
	din atac, as a safety net)
	- asa ca, in implementare, am ales sa iau
	deltax = b'1' * 32 + b'0' * 32, care nu ne afecteaza calculul
	si ne permite si sa:
		-> generam m1 aleator
		-> calculam m2 = m1 xor deltax
	ducand la generearea mai simpla a mesajelor
_______________________________________________________________


- o data ce am facut rost de perechile de mesaje (m1, m2) si
criptari (c1, c2), putem sa atacam k3 byte cu byte, in punctul
X = E'(k3, m) din schema de mai sus, folosind formula:

	E’(k, m) = R3 XOR S-box(k3 XOR L3)
		--- partea dreapta a mesajului xor S-box(k3 xor L3)
			--- R2 din S-box(k3 xor R2) este inlocuit cu L3,
			deoarece Li = Ri-1, din schema

- pentru fiecare byte din k3, fac brute force pe fiecare valoare
pe care o poate lua byte-ul din k3 =0...255 si iterez prin multimea
de valori (c1, c2) generate, calculez valoarea din punctul X dupa
formula discutata si calculez deltay = X1 xor X2
	---> aleg k31|k32|k33|k34 unde pentru valoarea lui k3i,
	am cele mai multe asocieri deltax == deltay

- calculez toata cheia, decriptez mesajul
