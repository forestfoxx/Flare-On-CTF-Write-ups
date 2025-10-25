
Flare-On 12 was my first time participating in this reverse
engineering challenge. While I couldn’t dedicate as much time as I
wanted to solving the tasks due to joining belatedly and having lots
of other stuff to take care of, I did manage to solve 4 tasks and
ponder on the 5th one. Below are some of my notes for
them.

**Challenge 1 – “Drill Baby Drill!”:**


The first challenge is a game written in Python. We could play the game (and fail
miserably by constantly drilling into stones) or analyze the source
code and try to find clues on solving the challenge.


```python
def GenerateFlagText(sum): 
  key = sum >> 8
  encoded = "\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9"
  plaintext = [] 
  for i in range(0, len(encoded)):
    plaintext.append(chr(ord(encoded[i]) ^ (key+i)))
  return ''.join(plaintext) 

for j in range (256, 2476100): 
  GenerateFlagText(j)
  if "flare" in GenerateFlagText(j):
    print(GenerateFlagText(j))
    break
```
For five
levels we need to have any combo with a product >= 256. The upper
bound is 2476099 (that is, 19x19x19x19x19, related to location number
-1 and amount of levels).

Running the script gets us the flag:


```drilling_for_teddies@flare-on.com```


**Challenge 2 - “project_chimera”:**

In this challenge we
need to understand how marshaling in Python works and analyze Python
bytecode in order to infer the logic to generate the flag. Over the
course of solving this challenge, I explored some decompilation tools
for Python – of those, I’d particularly mention [uncompyle](https://github.com/rocky/python-uncompyle6),
[decompile3](https://github.com/rocky/python-decompile3),
[pycdc](https://github.com/zrax/pycdc), and [pylingual](https://github.com/syssec-utd/pylingual),
which looks like the most capable of all existing solutions (see the
authors’ [paper](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a052/21B7QZB86cg)
for more). I also found it interesting to read up a bit on
obfuscating and [deobfuscating](https://github.com/Svenskithesource/PyArmor-Unpacker)
Python code with Pyarmor. The bad news about Python decompilation is
that it’s very version-specific (I recommend [this
blogpost](https://idafchev.github.io/blog/Decompile_python/) from Ilia Dafchev for some insights on decompiling
recent Python versions) It is also true of the marshal module, which
is quite a pain (in the end I had success with using python 3.12).
The good news is that we don’t actually need to do any
manipulations with .pyc files in this challenge (although learning
this stuff was a useful experience anyway), understanding the logic
in the bytecode is enough. Using the dis module on the code object
from the challenge, we can get this bytecode:




```py
 0           0 RESUME                   0 

 2           2 LOAD_CONST               0 (0) 
             4 LOAD_CONST               1 (None) 
             6 IMPORT_NAME              0 (base64) 
             8 STORE_NAME               0 (base64) 

 3          10 LOAD_CONST               0 (0) 
            12 LOAD_CONST               1 (None) 
            14 IMPORT_NAME              1 (zlib) 
            16 STORE_NAME               1 (zlib) 

 4          18 LOAD_CONST               0 (0) 
            20 LOAD_CONST               1 (None) 
            22 IMPORT_NAME              2 (marshal) 
            24 STORE_NAME               2 (marshal) 

 5          26 LOAD_CONST               0 (0) 
            28 LOAD_CONST               1 (None) 
            30 IMPORT_NAME              3 (types) 
            32 STORE_NAME               3 (types) 

 8          34 LOAD_CONST               2 (b'c$|e+O>7&-6`m!Rzak~llE|2<;!(^*VQn#qEH||xE2b$*W=zw8NW~2mgIMj3sFjzy%<NJQ84^$vqeTG&mC+yhlE677j-8)F4nD>~?<GqL64olvBs$bZ4{qE;{|=p@M4Abeb^*>CzIprJ_rCXLX1@k)54$HHULnIe5P-l)Ahj!*6w{D~l%XMwDPu#jDYhX^
DN{q5Q|5-Wq%1@lBx}}|vN1p~UI8h)0U&nS13Dg}x8K^E-(q$p0}4!ly-%m{0Hd>^+3*<O{*s0K-lk|}BLHWKJweQrNz5{%F-;@E_{d+ImTl7-o7&}O{%uba)w1RL*UARX*79t+0<^B?zmlODX9|2bzp_ztwjy_TdKb)1%eP4d-Xti0Ygjk_%w!^%1xuMNv4Z8&(*Ue7_^Fby1n3;+G<VDAfqi^h1>0@=Eki5!M~rms%
afx`+uxa0*;FzudpqNln5M<@!OqndZ)R<vh4u&gpmmnaMewbT0RJby?(fa7XW#r>ZQ4UE&u|~lZsEY~-lpfWMf0_+pV-H`PXInpwmyo~mZ`tfUK?($KHa%mvNlovZ;Y)D+e6uw+mY6LNB2Y9&akbWpZ@lh=Si<!J@t|CG86E`)jp!l4xEY(h7@$llA4}B9dpL*j)eL{vVcbyMx5_{b13)N@wa~epS8Zfo&V_Y#fM*g9;
@6%j=%i%WB0=QS3ewj@0~B!iibu<MqrrJIH{m&FoAGB3#0Nf;x!~dvQ|9#3c})IL6kEvhByJvA{B9%UqX0Tg*-+Ak~NW&RJbB?a6weENW&rzRi2ZB!647HWlA^rG4gvj3Yteo30&*};59;7nJF7eh7vjEXwwxPWWzD*3<IvZS#lIL(l*?u$;EGifKfLDpVb*rXLyw!AP~ZT^-S=4X{31tqe<O1kwG$gBZnu8eva3~6;4
CxrcH1{Qg{M;GT5@Bdqt%s{xkT;DyaBk)v>cTr#=XM@cQ-VZZJ1azh{1Df~fwf(mdYk_cEC``#zrevUuf1-I7DHKqx9c7Me?*iNur9a3~o)A1AmHbK!6#k<d+QmXjoUlrAc=R-8EfEvn$TP%?Zb2%`-;wF2Z7c~Qh!QUp%@F7d(Q;It@nl31iwc^NCTTrj*OW)bEH>BYlQ$YmihSV2QDxrCsKNToEmsNif~;-ILG+l$@
~sMDcnEHYIbjb?L-swo%>NNY60QJ5`2LX(&$CFf*W(cl7t80939@QH+>;!kK4jMTiOQA}zM@dS+wmk4?RtsqIs(NtuZr(Ewj<zxXaVots!6<}UP5>nNp1gfkes4T*zd{)6h-GF4>NSQO}R*91{c`k!=D-D}baN$1fuVNrUDvGiYVXWYBI456{mCG`ukuZfpN)A<xyb=s}byE(DvZfmpRkvo4CMg+F*3C%f6#?m{g@T4u
-G<~mB~wGXg;NVMFDj&f5<)qG1#7xlYdFEQ_jHRu*e&FUmQ1J<Gp}4$xq@yalC(x)S-FIEgQe+IxARLJPRm@DXx&t+<h5L0ORJ<E<cw}6ln6?exLHy}9_dE4pz17oL(~E`{a`E-no7?`5)pDEpNY(-6VaJ?C^<J9(GN!A;n`PTPDZBE;WN>5k=ams`uyy<xmZYd@Og|04{1U(*1PGLR>h3WX?aZWQf~69?j-FsmL^GvI
nrgidoM2}r1u&}XB+q}oGg-NR#n^X*4uqBy?1qY$4<jzMBhXA);zPfx3*xU!VW$#fFa&MCOfRHVn0%6k8aaRw9dY?)7!uP!nGHEb#k+JxY|2h>kX{N{%!`IfvPX|S@e!nA3Iy~#cKVr)%cFx{mYSGj9h1H_Q6edkhuGk)3Z9gWp`~mJzG74m7(!J^o(!2de`mO?3IDzcV;$RQ`@foiYHlj%{3;+>#iT|K>v-`YH)PTx#
fRu(|@AsKT#P^)cna!|9sUyU-MtAxP}M>w|Cc1s4_KI9hlp2y|UAEJ$C2$4Oh6~@uj-!Y-5tEyI$Y%KECN4u6l<*?fcwR_fD^|+djDIJ5u!>A&1N9itm{<3o-un;-)89^#pIPd{VwyzH_1WOyqZ$H)k$XXD-xcUafgjb=N#i!+Onn-Tj-cEob+(!(BOWa>FtC;21DH{%^IHo=c%;r;jstN15qS_U^F=Ab$c5Oh5W?fY!
%^vdXfE>5Yf!rHF^<aF`B*be*L=(CF(%-E<?)%b0$BJ)|f2ZjG%ISw+Z8XcC`j+)bpk<79YXWEkdaV7mwG_kiObaNYym&C&ix(EpA7N#?}|aRxAsRm;!2e%e)a4AvZnHUPvwCa?b&OiHoo') 
            36 STORE_NAME               4 (encoded_catalyst_strand) 

10          38 PUSH_NULL 
            40 LOAD_NAME                5 (print) 
            42 LOAD_CONST               3 ('--- Calibrating Genetic Sequencer ---') 
            44 CALL                     1 
            52 POP_TOP 

11          54 PUSH_NULL 
            56 LOAD_NAME                5 (print) 
            58 LOAD_CONST               4 ('Decoding catalyst DNA strand...') 
            60 CALL                     1 
            68 POP_TOP 

12          70 PUSH_NULL 
            72 LOAD_NAME                0 (base64) 
            74 LOAD_ATTR               12 (b85decode) 
            94 LOAD_NAME                4 (encoded_catalyst_strand) 
            96 CALL                     1 
           104 STORE_NAME               7 (compressed_catalyst) 

13         106 PUSH_NULL 
           108 LOAD_NAME                1 (zlib) 
           110 LOAD_ATTR               16 (decompress) 
           130 LOAD_NAME                7 (compressed_catalyst) 
           132 CALL                     1 
           140 STORE_NAME               9 (marshalled_genetic_code) 

14         142 PUSH_NULL 
           144 LOAD_NAME                2 (marshal) 
           146 LOAD_ATTR               20 (loads) 
           166 LOAD_NAME                9 (marshalled_genetic_code) 
           168 CALL                     1 
           176 STORE_NAME              11 (catalyst_code_object) 

16         178 PUSH_NULL 
           180 LOAD_NAME                5 (print) 
           182 LOAD_CONST               5 ('Synthesizing Catalyst Serum...') 
           184 CALL                     1 
           192 POP_TOP 

19         194 PUSH_NULL 
           196 LOAD_NAME                3 (types) 
           198 LOAD_ATTR               24 (FunctionType) 
           218 LOAD_NAME               11 (catalyst_code_object) 
           220 PUSH_NULL 
           222 LOAD_NAME               13 (globals) 
           224 CALL                     0 
           232 CALL                     2 
           240 STORE_NAME              14 (catalyst_injection_function) 

22         242 PUSH_NULL 
           244 LOAD_NAME               14 (catalyst_injection_function) 
           246 CALL                     0 
           254 POP_TOP 
           256 RETURN_CONST             1 (None) 
None

```

We can use
the information from the encoded const to peel off another layer:







```python
import zlib 
import base64 
import marshal 
import types 
import dis

encoded_catalyst_strand=b'c$|e+O>7&-6`m!Rzak~llE|2<;!(^*VQn#qEH||xE2b$*W=zw8NW~2mgIMj3sFjzy%<NJQ84^$vqeTG&mC+yhlE677j-8)F4nD>~?<GqL64olvBs$bZ4{qE;{|=p@M4Abeb^*>CzIprJ_rCXLX1@k)54$HHULnIe5P-l)Ahj!*6w{D~l%XMwDPu#jDYhX^DN{q5Q|5-Wq%1@lBx}}|
vN1p~UI8h)0U&nS13Dg}x8K^E-(q$p0}4!ly-%m{0Hd>^+3*<O{*s0K-lk|}BLHWKJweQrNz5{%F-;@E_{d+ImTl7-o7&}O{%uba)w1RL*UARX*79t+0<^B?zmlODX9|2bzp_ztwjy_TdKb)1%eP4d-Xti0Ygjk_%w!^%1xuMNv4Z8&(*Ue7_^Fby1n3;+G<VDAfqi^h1>0@=Eki5!M~rms%afx`+uxa0*;FzudpqNln
5M<@!OqndZ)R<vh4u&gpmmnaMewbT0RJby?(fa7XW#r>ZQ4UE&u|~lZsEY~-lpfWMf0_+pV-H`PXInpwmyo~mZ`tfUK?($KHa%mvNlovZ;Y)D+e6uw+mY6LNB2Y9&akbWpZ@lh=Si<!J@t|CG86E`)jp!l4xEY(h7@$llA4}B9dpL*j)eL{vVcbyMx5_{b13)N@wa~epS8Zfo&V_Y#fM*g9;@6%j=%i%WB0=QS3ewj@0
~B!iibu<MqrrJIH{m&FoAGB3#0Nf;x!~dvQ|9#3c})IL6kEvhByJvA{B9%UqX0Tg*-+Ak~NW&RJbB?a6weENW&rzRi2ZB!647HWlA^rG4gvj3Yteo30&*};59;7nJF7eh7vjEXwwxPWWzD*3<IvZS#lIL(l*?u$;EGifKfLDpVb*rXLyw!AP~ZT^-S=4X{31tqe<O1kwG$gBZnu8eva3~6;4CxrcH1{Qg{M;GT5@Bdqt
%s{xkT;DyaBk)v>cTr#=XM@cQ-VZZJ1azh{1Df~fwf(mdYk_cEC``#zrevUuf1-I7DHKqx9c7Me?*iNur9a3~o)A1AmHbK!6#k<d+QmXjoUlrAc=R-8EfEvn$TP%?Zb2%`-;wF2Z7c~Qh!QUp%@F7d(Q;It@nl31iwc^NCTTrj*OW)bEH>BYlQ$YmihSV2QDxrCsKNToEmsNif~;-ILG+l$@~sMDcnEHYIbjb?L-swo%
>NNY60QJ5`2LX(&$CFf*W(cl7t80939@QH+>;!kK4jMTiOQA}zM@dS+wmk4?RtsqIs(NtuZr(Ewj<zxXaVots!6<}UP5>nNp1gfkes4T*zd{)6h-GF4>NSQO}R*91{c`k!=D-D}baN$1fuVNrUDvGiYVXWYBI456{mCG`ukuZfpN)A<xyb=s}byE(DvZfmpRkvo4CMg+F*3C%f6#?m{g@T4u-G<~mB~wGXg;NVMFDj&f
5<)qG1#7xlYdFEQ_jHRu*e&FUmQ1J<Gp}4$xq@yalC(x)S-FIEgQe+IxARLJPRm@DXx&t+<h5L0ORJ<E<cw}6ln6?exLHy}9_dE4pz17oL(~E`{a`E-no7?`5)pDEpNY(-6VaJ?C^<J9(GN!A;n`PTPDZBE;WN>5k=ams`uyy<xmZYd@Og|04{1U(*1PGLR>h3WX?aZWQf~69?j-FsmL^GvInrgidoM2}r1u&}XB+q}o
Gg-NR#n^X*4uqBy?1qY$4<jzMBhXA);zPfx3*xU!VW$#fFa&MCOfRHVn0%6k8aaRw9dY?)7!uP!nGHEb#k+JxY|2h>kX{N{%!`IfvPX|S@e!nA3Iy~#cKVr)%cFx{mYSGj9h1H_Q6edkhuGk)3Z9gWp`~mJzG74m7(!J^o(!2de`mO?3IDzcV;$RQ`@foiYHlj%{3;+>#iT|K>v-`YH)PTx#fRu(|@AsKT#P^)cna!|9
sUyU-MtAxP}M>w|Cc1s4_KI9hlp2y|UAEJ$C2$4Oh6~@uj-!Y-5tEyI$Y%KECN4u6l<*?fcwR_fD^|+djDIJ5u!>A&1N9itm{<3o-un;-)89^#pIPd{VwyzH_1WOyqZ$H)k$XXD-xcUafgjb=N#i!+Onn-Tj-cEob+(!(BOWa>FtC;21DH{%^IHo=c%;r;jstN15qS_U^F=Ab$c5Oh5W?fY!%^vdXfE>5Yf!rHF^<aF`
B*be*L=(CF(%-E<?)%b0$BJ)|f2ZjG%ISw+Z8XcC`j+)bpk<79YXWEkdaV7mwG_kiObaNYym&C&ix(EpA7N#?}|aRxAsRm;!2e%e)a4AvZnHUPvwCa?b&OiHoo'

compressed_catalyst = base64.b85decode(encoded_catalyst_strand)
marshalled_genetic_code = zlib.decompress(compressed_catalyst)
catalyst_code_object = marshal.loads(marshalled_genetic_code)
disasm = dis.dis(catalyst_code_object) 
print(disasm)
```


This script shows us the bytecode that we actually need to finally solve
the challenge:



```py
 0           0 RESUME                   0 

 2           2 LOAD_CONST               0 (0) 
             4 LOAD_CONST               1 (None) 
             6 IMPORT_NAME              0 (os) 
             8 STORE_NAME               0 (os) 

 3          10 LOAD_CONST               0 (0) 
            12 LOAD_CONST               1 (None) 
            14 IMPORT_NAME              1 (sys) 
            16 STORE_NAME               1 (sys) 

 4          18 LOAD_CONST               0 (0) 
            20 LOAD_CONST               1 (None) 
            22 IMPORT_NAME              2 (emoji) 
            24 STORE_NAME               2 (emoji) 

 5          26 LOAD_CONST               0 (0) 
            28 LOAD_CONST               1 (None) 
            30 IMPORT_NAME              3 (random) 
            32 STORE_NAME               3 (random) 

 6          34 LOAD_CONST               0 (0) 
            36 LOAD_CONST               1 (None) 
            38 IMPORT_NAME              4 (asyncio) 
            40 STORE_NAME               4 (asyncio) 

 7          42 LOAD_CONST               0 (0) 
            44 LOAD_CONST               1 (None) 
            46 IMPORT_NAME              5 (cowsay) 
            48 STORE_NAME               5 (cowsay) 

 8          50 LOAD_CONST               0 (0) 
            52 LOAD_CONST               1 (None) 
            54 IMPORT_NAME              6 (pyjokes) 
            56 STORE_NAME               6 (pyjokes) 

 9          58 LOAD_CONST               0 (0) 
            60 LOAD_CONST               1 (None) 
            62 IMPORT_NAME              7 (art) 
            64 STORE_NAME               7 (art) 

10          66 LOAD_CONST               0 (0) 
            68 LOAD_CONST               2 (('ARC4',)) 
            70 IMPORT_NAME              8 (arc4) 
            72 IMPORT_FROM              9 (ARC4) 
            74 STORE_NAME               9 (ARC4) 
            76 POP_TOP 

15          78 LOAD_CONST               3 (<code object activate_catalyst at 0x240cdc0, file "<catalyst_core>", line 15>) 
            80 MAKE_FUNCTION            0 
            82 STORE_NAME              10 (activate_catalyst) 

54          84 PUSH_NULL 
            86 LOAD_NAME                4 (asyncio) 
            88 LOAD_ATTR               22 (run) 
           108 PUSH_NULL 
           110 LOAD_NAME               10 (activate_catalyst) 
           112 CALL                     0 
           120 CALL                     1 
           128 POP_TOP 
           130 RETURN_CONST             1 (None) 

Disassembly of <code object activate_catalyst at 0x240cdc0, file "<catalyst_core>", line 15>: 
15           0 RETURN_GENERATOR 
             2 POP_TOP 
             4 RESUME                   0 

16           6 LOAD_CONST               1 (b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS') 
             8 STORE_FAST               0 (LEAD_RESEARCHER_SIGNATURE) 

17          10 LOAD_CONST               2 (b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90') 
            12 STORE_FAST               1 (ENCRYPTED_CHIMERA_FORMULA) 

19          14 LOAD_GLOBAL              1 (NULL + print) 
            24 LOAD_CONST               3 ('--- Catalyst Serum Injected ---') 
            26 CALL                     1 
            34 POP_TOP 

20          36 LOAD_GLOBAL              1 (NULL + print) 
            46 LOAD_CONST               4 ("Verifying Lead Researcher's credentials via biometric scan...") 
            48 CALL                     1 
            56 POP_TOP 

22          58 LOAD_GLOBAL              3 (NULL + os) 
            68 LOAD_ATTR                4 (getlogin) 
            88 CALL                     0 
            96 LOAD_ATTR                7 (NULL|self + encode) 
           116 CALL                     0 
           124 STORE_FAST               2 (current_user) 

25         126 LOAD_GLOBAL              9 (NULL + bytes) 
           136 LOAD_CONST               5 (<code object <genexpr> at 0x7efd08e8d630, file "<catalyst_core>", line 25>) 
           138 MAKE_FUNCTION            0 
           140 LOAD_GLOBAL             11 (NULL + enumerate) 
           150 LOAD_FAST                2 (current_user) 
           152 CALL                     1 
           160 GET_ITER 
           162 CALL                     0 
           170 CALL                     1 
           178 STORE_FAST               3 (user_signature) 

27         180 LOAD_GLOBAL             13 (NULL + asyncio) 
           190 LOAD_ATTR               14 (sleep) 
           210 LOAD_CONST               6 (0.01) 
           212 CALL                     1 
           220 GET_AWAITABLE            0 
           222 LOAD_CONST               0 (None) 
       >>  224 SEND                     3 (to 234) 
           228 YIELD_VALUE              2 
           230 RESUME                   3 
           232 JUMP_BACKWARD_NO_INTERRUPT     5 (to 224) 
       >>  234 END_SEND 
           236 POP_TOP 

29         238 LOAD_CONST               7 ('pending') 
           240 STORE_FAST               4 (status) 

30         242 LOAD_FAST                4 (status) 

31         244 LOAD_CONST               7 ('pending') 
           246 COMPARE_OP              40 (==) 
           250 EXTENDED_ARG             1 
           252 POP_JUMP_IF_FALSE      294 (to 842) 

32         254 LOAD_FAST                3 (user_signature) 
           256 LOAD_FAST                0 (LEAD_RESEARCHER_SIGNATURE) 
           258 COMPARE_OP              40 (==) 
           262 POP_JUMP_IF_FALSE      112 (to 488) 

33         264 LOAD_GLOBAL             17 (NULL + art) 
           274 LOAD_ATTR               18 (tprint) 
           294 LOAD_CONST               8 ('AUTHENTICATION   SUCCESS') 
           296 LOAD_CONST               9 ('small') 
           298 KW_NAMES                10 (('font',)) 
           300 CALL                     2 
           308 POP_TOP 

34         310 LOAD_GLOBAL              1 (NULL + print) 
           320 LOAD_CONST              11 ('Biometric scan MATCH. Identity confirmed as Lead Researcher.') 
           322 CALL                     1 
           330 POP_TOP 

35         332 LOAD_GLOBAL              1 (NULL + print) 
           342 LOAD_CONST              12 ('Finalizing Project Chimera...') 
           344 CALL                     1 
           352 POP_TOP 

37         354 LOAD_GLOBAL             21 (NULL + ARC4) 
           364 LOAD_FAST                2 (current_user) 
           366 CALL                     1 
           374 STORE_FAST               5 (arc4_decipher) 

38         376 LOAD_FAST                5 (arc4_decipher) 
           378 LOAD_ATTR               23 (NULL|self + decrypt) 
           398 LOAD_FAST                1 (ENCRYPTED_CHIMERA_FORMULA) 
           400 CALL                     1 
           408 LOAD_ATTR               25 (NULL|self + decode) 
           428 CALL                     0 
           436 STORE_FAST               6 (decrypted_formula) 

41         438 LOAD_GLOBAL             27 (NULL + cowsay) 
           448 LOAD_ATTR               28 (cow) 
           468 LOAD_CONST              13 ('I am alive! The secret formula is:\n') 
           470 LOAD_FAST                6 (decrypted_formula) 
           472 BINARY_OP                0 (+) 
           476 CALL                     1 
           484 POP_TOP 
           486 RETURN_CONST             0 (None) 

43     >>  488 LOAD_GLOBAL             17 (NULL + art) 
           498 LOAD_ATTR               18 (tprint) 
           518 LOAD_CONST              14 ('AUTHENTICATION   FAILED') 
           520 LOAD_CONST               9 ('small') 
           522 KW_NAMES                10 (('font',)) 
           524 CALL                     2 
           532 POP_TOP 

44         534 LOAD_GLOBAL              1 (NULL + print) 
           544 LOAD_CONST              15 ('Impostor detected, my genius cannot be replicated!') 
           546 CALL                     1 
           554 POP_TOP 

45         556 LOAD_GLOBAL              1 (NULL + print) 
           566 LOAD_CONST              16 ('The resulting specimen has developed an unexpected, and frankly useless, sense of humor.') 
           568 CALL                     1 
           576 POP_TOP 

47         578 LOAD_GLOBAL             31 (NULL + pyjokes) 
           588 LOAD_ATTR               32 (get_joke) 
           608 LOAD_CONST              17 ('en') 
           610 LOAD_CONST              18 ('all') 
           612 KW_NAMES                19 (('language', 'category')) 
           614 CALL                     2 
           622 STORE_FAST               7 (joke) 

48         624 LOAD_GLOBAL             26 (cowsay) 
           634 LOAD_ATTR               34 (char_names) 
           654 LOAD_CONST              20 (1) 
           656 LOAD_CONST               0 (None) 
           658 BINARY_SLICE 
           660 STORE_FAST               8 (animals) 

49         662 LOAD_GLOBAL              1 (NULL + print) 
           672 LOAD_GLOBAL             27 (NULL + cowsay) 
           682 LOAD_ATTR               36 (get_output_string) 
           702 LOAD_GLOBAL             39 (NULL + random) 
           712 LOAD_ATTR               40 (choice) 
           732 LOAD_FAST                8 (animals) 
           734 CALL                     1 
           742 LOAD_GLOBAL             31 (NULL + pyjokes) 
           752 LOAD_ATTR               32 (get_joke) 
           772 CALL                     0 
           780 CALL                     2 
           788 CALL                     1 
           796 POP_TOP 

50         798 LOAD_GLOBAL             43 (NULL + sys) 
           808 LOAD_ATTR               44 (exit) 
           828 LOAD_CONST              20 (1) 
           830 CALL                     1 
           838 POP_TOP 
           840 RETURN_CONST             0 (None) 

51     >>  842 NOP 

52         844 LOAD_GLOBAL              1 (NULL + print) 
           854 LOAD_CONST              21 ('System error: Unknown experimental state.') 
           856 CALL                     1 
           864 POP_TOP 
           866 RETURN_CONST             0 (None) 

27     >>  868 CLEANUP_THROW 
           870 EXTENDED_ARG             1 
           872 JUMP_BACKWARD          320 (to 234) 
       >>  874 CALL_INTRINSIC_1         3 (INTRINSIC_STOPITERATION_ERROR) 
           876 RERAISE                  1 
ExceptionTable: 
 4 to 226 -> 874 [0] lasti 
 228 to 228 -> 868 [2] 
 230 to 868 -> 874 [0] lasti 

Disassembly of <code object <genexpr> at 0x7efd08e8d630, file "<catalyst_core>", line 25>: 
25           0 RETURN_GENERATOR 
             2 POP_TOP 
             4 RESUME                   0 
             6 LOAD_FAST                0 (.0) 
       >>    8 FOR_ITER                15 (to 42) 
            12 UNPACK_SEQUENCE          2 
            16 STORE_FAST               1 (i) 
            18 STORE_FAST               2 (c) 
            20 LOAD_FAST                2 (c) 
            22 LOAD_FAST                1 (i) 
            24 LOAD_CONST               0 (42) 
            26 BINARY_OP                0 (+) 
            30 BINARY_OP               12 (^) 
            34 YIELD_VALUE              1 
            36 RESUME                   1 
            38 POP_TOP 
            40 JUMP_BACKWARD           17 (to 8) 
       >>   42 END_FOR 
            44 RETURN_CONST             1 (None) 
       >>   46 CALL_INTRINSIC_1         3 (INTRINSIC_STOPITERATION_ERROR) 
            48 RERAISE                  1 
ExceptionTable: 
 4 to 44 -> 46 [0] lasti 
None

```

Now we can create the final script by analyzing
the logic at the end of the bytecode (failing to ‘authenticate’
will just give us some cowsay memes, as we can see either from
manually trying to run it or by reading the bytecode):


```python
from arc4 import ARC4 
LEAD_RESEARCHER_SIGNATURE = b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS' 
ENCRYPTED_CHIMERA_FORMULA = b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90'
username_bytes = bytes(signature_byte ^ (i + 42) for i, signature_byte in enumerate(LEAD_RESEARCHER_SIGNATURE)) 
username = username_bytes.decode() 
print(f"Computed username: {username}") 
computed_signature = bytes(c ^ (i + 42) for i, c in enumerate(username_bytes)) 
assert computed_signature == LEAD_RESEARCHER_SIGNATURE, "Signature verification failed" 
print("Signature verification passed: computed signature matches LEAD_RESEARCHER_SIGNATURE")
cipher = ARC4(username_bytes) 
decrypted = cipher.decrypt(ENCRYPTED_CHIMERA_FORMULA) 
flag = decrypted.decode() 
print(f"Decrypted flag: {flag}")
```

After running the above script, we get the flag:

>Computed username: G0ld3n_Tr4nsmut4t10n

>Signature verification passed: computed signature matches LEAD_RESEARCHER_SIGNATURE

>Decrypted flag: ```Th3_Alch3m1sts_S3cr3t_F0rmul4@flare-on.com```







**Challenge 3 - “pretty_devilish_file”:**



Here we need to analyze a ‘devilish’ pdf
file. Speaking of which, it’s always good praxis to analyze
suspicious files in an isolated environment. For reverse engineering
tasks specifically, Windows-based [Flare-VM](https://github.com/mandiant/flare-vm)
from Mandiant (who happen to be the organizers of the challenge)
or Linux-based [REMnux](https://github.com/REMnux) are
convenient choices with plenty of useful tools preinstalled.








Initially,
I mused quite a bit with pdf internals and various analysis tools,
including [binwalk](https://github.com/ReFirmLabs/binwalk),
[pdfalyzer](https://github.com/michelcrypt4d4mus/pdfalyzer),
[polytracker](https://github.com/trailofbits/polytracker),
[peepdf](https://github.com/jesparza/peepdf), [qpdf](https://github.com/qpdf/qpdf),
as well as tools and materials by [Didier
Stevens](https://blog.didierstevens.com/category/pdf/). Analyzing the pdf structure, I found some strange
headers relating to NRO and SNDH (which are related to Atari ST music
formats and Nintendo Switch binaries). I did try to find some loaders
for those for [Ghidra](https://github.com/Adubbz/Ghidra-Switch-Loader)
and [IDA](https://github.com/pgarba/SwitchIDAProLoader),
but quickly realized that these headers were probably just deception,
not some smart embedding scheme. Looking at the pdf structure, I
inferred some AES encryption (passwordless) as well as some stream
data in object 4 which might have been of use. That said, the pdf
structure was actually broken (including missing xref table and other
things), obviously intentionally. I wasn’t sure if I should have
tried fixing the structure manually, so I took a step back and tried
another approach – I loaded the pdf into Inkscape and, besides the
“Flare-On” picture, found a suspicious separate area, extracted
it and tried to find out whether it could have had an embedded flag
or something like that. It proved to be true, and I managed to
extract the flag from the image:







```python
from pathlib import Path
from PIL import Image
IMG_PATH = Path("image1.png") 
NUM_PIXELS = 37                 
ORDER = "row"              
def load_grayscale(path: Path) -> Image.Image:
  img = Image.open(path)
  if img.mode != "L":
    img = img.convert("L")
  return img
def pixel_coords(width: int, height: int, order: str):
    if order == "row":
        for y in range(height):
            for x in range(width):
                yield x, y
    elif order == "col":
        for x in range(width):
            for y in range(height):
                yield x, y

def extract_values(img: Image.Image, n: int, order: str):
    w, h = img.size
    vals = []
    for x, y in pixel_coords(w, h, order):
        vals.append(img.getpixel((x, y)))
        if len(vals) == n:
            break
    return vals

def try_decode(byte_vals):
    b = bytes(byte_vals)
    try:
        txt = b.decode("utf-8")
        if any(c.isprintable() for c in txt):
            return txt
    except UnicodeDecodeError:
        pass

def main():
    img = load_grayscale(IMG_PATH)
    values = extract_values(img, NUM_PIXELS, ORDER)
    print("Grayscale values (decimal):")
    print(values)
    decoded = try_decode(values)
    print("\nDecoded text:")
    print(decoded)
if __name__ == "__main__":
    main()
```







Which gave me the flag:

>Grayscale values (decimal): 

>[80, 117, 122, 122, 108, 49, 110, 103, 45, 68, 51, 118, 105, 108, 105, 115, 104, 45, 70, 48, 114, 109, 97, 116, 64, 102, 108, 97, 114, 101, 45, 111, 110, 46, 99, 111, 109] 

>Decoded text: ```Puzzl1ng-D3vilish-F0rmat@flare-on.com```



There was probably also a way to do this by continuing on the path of
digging into the pdf structure, but since this solution works as
well, it’s all good :)


**Challenge 4 – “UnholyDragon”:**



This one ended up much easier than I initially
thought, but documenting my thought process is good anyway.


In this challenge we’re presented with an
.exe file which fails to execute – analyzing the hexdump quickly
gives a clue why – the first byte is 15 and not 4D – patching it
to be 4D 5A – the well-known magic number – makes the executable
runnable again.



Running out “UnholyDragon-150.exe” binary
produces several copies of the binary with incrementing numbers (151,
152, 153, 154) and an open window for many (but apparently not all)
of them. But in fact they are not exact copies and differ in one byte
(some useful bindiffing tools include [bindiff](https://github.com/google/bindiff),
[diaphora](https://github.com/joxeankoret/diaphora), the
UNIX [cmp utility](https://www.man7.org/linux/man-pages/man1/cmp.1.html), [ghidriff](https://github.com/clearbluejar/ghidriff),
[BindiffHelper](https://github.com/ubfx/BinDiffHelper) and
radare2’s [radiff2](https://book.rada.re/tools/radiff2/intro.html)
utility). Analyzing its internals in Ghidra I also found mentions of
using twinbasic (?) as well as understood the fact that the changing
byte is related to dynamic kernel heap allocation (Mandiant’s [capa](https://github.com/mandiant/capa)
is also an excellent tool to get a quick rundown of an executable’s
capabilities, it reported for example a bunch of obfuscation
mechanisms, RC4 encryption, XORing and so on).



Further tinkering with the binary, I
understood that if we change the name of the binary, for example, to
“UnholyDragon-1.exe” (or anything else even not retaining such
naming convention), it will generate tons of binaries all the way up
to 154. Thanks to that I found out that the binary which makes the
150th one broken is the previous one, 149th
one, which overwrites the first byte of 150th one, making
it unrunnable. Also, the largest diff is from 150 to 151 – more
than one byte.



Speaking of the abovementioned 1-byte changes
in the binaries, the change is deterministic (changing the byte in
the binary manually and then running the previous one will return it
to its deterministic change). The new value is different in each
subsequent binary – e.g. the change is from byte 5c to 94 for
150.exe to 151.exe, then from 0d to 43 for 151.exe to 152.exe and so
on), so it seemed to depend on the previous value. The changed values
are also located on the same offset in a pair of different binaries.
Furthermore, the change operation is XOR the original byte with some
value to get the next byte.



While continuing to tinker with the binaries
and launching them, I ended up stumbling upon the flag which was
embedded in one of the opened windows after I launched the 150th
one :D. As I said, getting the flag ended up much easier than I
thought, but I really enjoyed the whole thought process anyway, even
if someone might say I was overthinking this basically easter egg
challenge. In the end, the key to this challenge “autosolving”
itself was to rename one of the binaries to a different name without
a number (e.g. “test.exe”) so that it could generate the whole
chain of binaries from UnholyDragon-1.exe to UnholyDragon-154.exe,
then fixing the 150th binary which was broken by the 149th
one, and running the 150th one to get the destined window
with the dragon and a flag.

<img width="1643" height="962" alt="dragon" src="https://github.com/user-attachments/assets/02c69e4e-92dc-4591-a2cb-3d8778d65133" />

**Challenge 5 – “ntfsm”:**

In this task we’re presented with a single executable which, judging by its internals in Ghidra,
is some sort of state machine with lots of execution paths (and
plenty of rickrolls). Launching it from the command line and giving
it some password, the output tells us to input 16 characters. Doing
that, we get precisely 16 windows opened saying “Hello there,
Hacker!”, which is one of many trick messages we can find by
analyzing the binary.

To be continued...

