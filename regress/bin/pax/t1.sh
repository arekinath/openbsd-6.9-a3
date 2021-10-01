#!/bin/sh
# $OpenBSD: t1.sh,v 1.1 2005/04/14 15:17:07 cloder Exp $

# pax was assuming ustar entries were always NUL terminated
CUR=$1
OBJ=$2
uudecode -o $OBJ/t1.tar << '_EOF'
begin 644 t1.tar
M9&EG:6MA;6EM86=E<&QU9VEN<RTP+C<N,B]D:6=I:V%M:6UA9V5P;'5G:6YS
M+V%N=&EV:6=N971T:6YG+V1I9VEK86UI;6%G97!L=6=I;E]A;G1I=FEG;F5T
M=&EN9U]U:2YR8S`P,#`V-#0`,#`P,#<V-0`P,#`P-S8T`#`P,#`P,#`P-3(V
M`#$P,C`P,S,Q,#<T`#`S-3,T-``@,```````````````````````````````
M````````````````````````````````````````````````````````````
M``````````````````````````````````````````!U<W1A<B`@`&=I;&QE
M<P``````````````````````````````````9VEL;&5S````````````````
M```````````````````P,#`P,#`P`#`P,#`P,#``````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M```````````````````````\(41/0U194$4@:W!A<G1G=6D@4UE35$5-(")K
M<&%R=&=U:2YD=&0B/@H\:W!A<G1G=6D@=F5R<VEO;CTB,2(@;F%M93TB9&EG
M:6MA;6EM86=E<&QU9VEN7V%N=&EV:6=N971T:6YG(B`^"@H@/$UE;G5"87(^
M"@H@(#Q-96YU(&YA;64](D9I>"(@/@H@("`\=&5X=#Y&:29A;7`[>#PO=&5X
M=#X*("`@/$%C=&EO;B!N86UE/2)I;6%G97!L=6=I;E]A;G1I=FEG;F5T=&EN
M9R(@+SX@"B`@/"]-96YU/@H*(#PO365N=4)A<CX*(`H@/%1O;VQ"87(@;F%M
M93TB5&]O;$)A<B(@/@H@(#QT97AT/DUA:6X@5&]O;&)A<CPO=&5X=#X*(#PO
M5&]O;$)A<CX*"B`\06-T:6]N4')O<&5R=&EE<R\^"@H\+VMP87)T9W5I/@H`
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
B````````````````````````````````````````````````
`
end
_EOF

tar tf $OBJ/t1.tar 2> /dev/null | cmp -s $CUR/t1.out /dev/stdin
