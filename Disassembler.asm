.model small
.stack 100h
.data 
	fileName   	db 20 DUP (?) 								;duomenu failo pavadinimo buferis
	rezName		db 20 dup (?)								;rezultatu failo pavadinimo buferis
	fileHandle 	dw ?										;duomenu failo handleris
	rezHandle	dw ?										;rezultatu failo handleris
	fileErrorMsg db 'Klaida skaitant faila', '$'				;klaidos zinute duomenu
	rezErrorMsg db 'Klaida sukuriant faila', '$'				;klaidos zinute rezultatu
	
	neatpazinta db 'NEATPAZINTA', '$'								
	helpMsg 	db 'Gediminas Krasauskas I kursas 3 grupe $'	
	enteris 	db 13,10,'$'								;nauja eilute
	
	RegistruMasyvas db 'BX + SI BX + DI BP + SI BP + DI SI      DI      BP      BX     ', '$'
	PrintRegMasyvas db 8 dup ('$')
	
	fileEnd    	db 0										;ar failo pabaiga
	fileBuffer 	db 25 DUP (?)							    ;kazkoks baitu gabalas kuri analizuoja
	bufByte    	db ?										;momentinis baitas buferio gabale
	
	IPs			db 0										;IP simtai
	IPv			db 0										;IP vienetai
	temp 		dw 0
	double		dw 0
	
	BufBetOp	db 2 dup ('$')
	bufIP		db 4 dup ('$')
	bufMAS		db 14 dup ('$')
	
	kiekSp		dw 0
	kiekBaitu   dw 0
	masKodas	db 7 dup ('$')								;masininis kodas
	IPc 		dw 0100h									;IP counter - IP reiksme
	prefix     	dw 0										;prefiksas 1-taip 0-ne
	prefixType 	db 0										;prefikso kodas
	OPK			db 0										;operacijos kodas
	ADB			db 0										;adresavimo baitas
	poslj		db 0										;poslinkis jaunesnysis baitas
	poslv		db 0										;poslinkis vyresnysis baitas
	BetOpjb		db 0										;betarpinio operando jaunesnysis baitas
	BetOpvb		db 0 										;betarpinio operando vyresnysis baitas
	
  ; simboliai
	skliaustas1 db '[', '$'
	skliaustas2 db ']', '$'
	kablelis 	db ',', '$'
	pliusas 	db '+', '$'
	tarpas 		db ' ', '$'
	dvitaskis	db ':', '$'	
  ; w - 0 registrai
  rb_000     db 'AL ', '$'
  rb_001     db 'CL ', '$'
  rb_010     db 'DL ', '$'
  rb_011     db 'BL ', '$'
  rb_100     db 'AH ', '$'
  rb_101     db 'CH ', '$'
  rb_110     db 'DH ', '$'
  rb_111     db 'BH ', '$'
  ; w - 1 registrai
  rw_000    db 'AX ', '$'
  rw_001    db 'CX ', '$'
  rw_010    db 'DX ', '$'
  rw_011    db 'BX ', '$'
  rw_100    db 'SP ', '$'
  rw_101    db 'BP ', '$'
  rw_110    db 'SI ', '$'
  rw_111    db 'DI ', '$'
  ; segmentu registrai
  s_regES   db 'ES ', '$'
  s_regCS   db 'CS ', '$'
  s_regSS   db 'SS ', '$'
  s_regDS   db 'DS ', '$'
  ; r/m adresavimo budai
  rm_000    db 'BX + SI ', '$'
  rm_001    db 'BX + DI ', '$'
  rm_010    db 'BP + SI ', '$'
  rm_011    db 'BP + DI ', '$'
  rm_100    db 'SI ', '$'
  rm_101    db 'DI ', '$'
  rm_110    db 'BP ', '$'
  rm_111    db 'BX ', '$'
  
  word_ptr  db 'word ptr ', '$'
  byte_ptr  db 'byte ptr ', '$'

	opADD         db    'ADD  ', '$'				
	opCALL        db    'CALL ', '$'				
	opCMP         db    'CMP  ', '$'				
	opDEC         db    'DEC  ', '$'				
	opDIV         db    'DIV  ', '$'				
	opINC         db    'INC  ', '$'				
	opINT         db    'INT  ', '$'
	opJE		  db 	'JE   ', '$'
	opJA          db    'JA   ', '$'					
	opJP          db    'JP   ', '$'					
	opJAE         db    'JAE  ', '$'							
	opJBE         db    'JBE  ', '$'				
	opJCXZ        db    'JCXZ ', '$'				
	opJG          db    'JG   ', '$'					
	opJGE         db    'JGE  ', '$'				
	opJL          db    'JL   ', '$'						
	opJLE         db    'JLE  ', '$'				
	opJMP         db    'JMP  ', '$'								
	opJNO         db    'JNO  ', '$'				
	opJNS         db    'JNS  ', '$'			
	opJNP		  db	'JNP  ', '$'
	opJNAE		  db	'JNAE ', '$'
	opJO          db    'JO   ', '$'									
	opJS          db    'JS   ', '$'					
	opJNE		  db	'JNE  ', '$'		
	opLOOP        db    'LOOP ', '$'				
	opMOV         db    'MOV  ', '$'				
	opMUL         db    'MUL  ', '$'				
	opPOP         db    'POP  ', '$'				
	opPUSH        db    'PUSH ', '$'				
	opRET         db    'RET  ', '$'				
	opSUB         db    'SUB  ', '$'
	opNOT	db 	'NOT  ', '$'
	
.code
Programa:
	mov ax, @data
	mov ds, ax
	
	call prepareFile
	
	mov si, 0
    mov di, 0

__analyzeNewOp:
	call print_Ip
	lea dx, dvitaskis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call cleanAllArguments
    call readByte
    mov dh, 0
    mov dl, bufByte		;dx - 00XX 	xx - nuskaitytas baitas
    call arPrefix       	;analizuot dl (bufByte)
	call recognizeOp
	jmp __analyzeNewOp
	
;----------------------------------------------------------------------------------------------------------------------------------------;
;---------------------------------------------------------------PROCEDUROS---------------------------------------------------------------;
;----------------------------------------------------------------------------------------------------------------------------------------;

;----------------------------------------------------------PAGALBOS PRANESIMO SPAUSDINIMAS----------------------------------------------------------;
print_help proc
	mov ax, 0900h													;40h - rasymas i faila 
	mov dx, offset helpMsg													;load effective address , dx - rasymo buferio adresas
	int 21h 
	ret
print_help endp

;---------------------------------------------------------PARAMETRAI FAILU ATIDARYMAS--------------------------------------------------------------;
prepareFile proc 
	mov	ch, 0			
	mov	cl, es:0080h						;programos paleidimo parametrų simbolių skaičius 
	cmp	cx, 0								;jei paleidimo parametrų nėra,
	je __help
	jmp __ParYra
__ParYra:	
	mov bx, 0081h  							;programos paleidimo parametrai rasomi segmente es pradedant 129 (arba 81h) baitu
    mov di, 0								;tekstinio failo pavadinimo numeris
__ParTarp:	
	mov al, es:bx 
	inc bx  
    cmp al, ' '	
	je __ParTarp
	dec bx
__duomSeek:  
    mov al, es:bx 
	inc bx  
    cmp al, ' '		
    je __rezSeek0							
	cmp	es:bx, '?/'					
	je __help
	jmp __helpNe
__help:
	call print_help
	call endProgram
	ret
__helpNe:
    mov [fileName + di], al
    inc di
    jmp __duomSeek
__rezSeek0:
	mov di, 0
__rezSeek:
	mov al, es:bx 
	inc bx  
    cmp al, ' '		
    je __rezSeek
	cmp al, 0Dh
	je __parEnd
	cmp	es:bx, '?/'					
	je __help
	jmp __helpNeRez
__helpNeRez:
	mov [rezName + di], al
    inc di
    jmp __rezSeek
	
__parEnd:
    mov ax, 3D00h  							; atidaryt faila (al- 0 - read)
    mov dx, offset fileName
    int 21h
    jc __fileError							;jei carry flag, reiskia eroras
    jmp __noErrors							;jei ne, tai viskas gerai
__fileError: 
    call fileError
__noErrors:
    mov fileHandle, ax	
	
	mov ah, 3Ch								;3Ch - failo sukurimas
	mov cx, 0								;cx - failo atributai
	mov dx, offset rezName					;dx - rezultatu failo pavadinimo eilutes adresas
	int 21h
	jc __rezErrors							;jei yra pernesimas (carry flag=1)
	jmp __NoRezErrors
__rezErrors:
	call rezError
__NoRezErrors:
	mov rezHandle, ax
	
	ret
prepareFile endp
;------------------------------------------------KLAIDU DIRBANT SU FAILAIS SPAUSDINIMAS------------------------------------------------------------------;

fileError proc 
    call writeOffsetBuffer 
    call endProgram
	ret
fileError endp  

rezError proc
	call writeOffsetError 
    call endProgram
	ret
rezError endp

writeOffsetBuffer proc 
    mov ax, 0900h
    mov dx, offset fileErrorMsg
    int 21h
	ret
writeOffsetBuffer endp  

writeOffsetError proc
	mov ax, 0900h
    mov dx, offset rezErrorMsg
    int 21h
	ret
writeOffsetError endp
;-------------------------------------------------BAIGIAM PROGRAMA------------------------------------------------------------------;

endProgram proc
	mov ah, 3Eh
	mov bx, rezHandle
	int 21h

    mov ax, 4C00h
    int 21h
	ret
endProgram endp
;-----------------------------------------------KINTAMUJU APNULINIMAS------------------------------------------------------------------;

cleanAllArguments proc
	mov kiekBaitu, 0
	
	push si
	mov cx, 7
	mov si, 0
__clearMachine:
	mov [masKodas+si], '$'
	inc si
	loop __clearMachine

	mov cx, 13
	mov si, 0
__clearMachine1:
	mov [bufMAS+si], 20h
	inc si
	loop __clearMachine1
	mov [bufMAS+13], '$'
	
	pop si

    ret
cleanAllArguments endp
;----------------------------------------------FAILU SKAITYMAS----------------------------------------------------------------;
	
readByte proc
    ; si - dabartine pozicija fileBufferyje
    ; di - kiek baitu perskaityta
    cmp si, di
    je __readNewBuffer
    jmp __readByte
   
__readNewBuffer: 
    cmp fileEnd, 1
    je __endProgram
    mov ax, 3F00h						;skaitymas is failo
    mov dx, offset fileBuffer			;dx - skaitymo buferio adresas
    mov bx, fileHandle					;bx - deskriptorius/handleris		
    mov cx, 25							;cx - kiek baitu norim nuskaityti	
    int 21h         
    mov di, ax							;ax - kiek baitu nuskaityta
    mov si, 0
    cmp di, 25
    jl __EOF
    jmp __readByte
__endProgram:
    call endProgram   
__EOF:
    mov fileEnd, 1
    call closeFile  
__readByte:  
    inc IPc         					;IPc pakyla 1 kiekvienam bitui
    mov al, [fileBuffer + si]
    inc si
    mov bufByte, al	 
	ret 
readByte endp   
;-------------------------------------------FAILO UZDARYMAS----------------------------------------------------------------------;	
	
closeFile proc 
    mov ax, 3E00h				
    mov bx, fileHandle
    int 21h
    ret
closeFile endp 	
	
;----------------------------------------------------------------------------------------------------------------------------------------;
;---------------------------------------------------------------SPAUSDINIMAI-------------------------------------------------------------;
;----------------------------------------------------------------------------------------------------------------------------------------;

;-----------------------------------------------------NEATPAZINTA KOMANDA-----------------------------------------------------------;
print_Neatpazinta proc
	mov cx, 11														;cx - kiek baitu norima irasyti
	mov ah, 40h													;40h - rasymas i faila 
	mov bx, rezHandle										;failo deskriptorius (handleris)
	lea dx, neatpazinta													;load effective address , dx - rasymo buferio adresas
	int 21h 
	ret
print_Neatpazinta endp	
;-----------------------------------------------------ENTER (NAUJA EILUTE)----------------------------------------------------------------;
print_Enteris proc
	mov cx, 2														;cx - kiek baitu norima irasyti
	mov ah, 40h													;40h - rasymas i faila 
	mov bx, rezHandle											;failo deskriptorius (handleris)
	lea dx, enteris													;load effective address , dx - rasymo buferio adresas
	int 21h 
	ret
print_Enteris endp
;------------------------------------------------------IP REIKSME-----------------------------------------------------------------;

Tikrina_IP proc  
	cmp al, 09h
	ja __RaideIP
	jmp __SkaiciusIP
__RaideIP:
	add al, 37h 
	mov [bufIP+si], al
	inc si
__SkaiciusIP:
	add al, 30h  
	mov [bufIP+si], al
	inc si
	ret     
Tikrina_IP endp  

print_Ip proc
	push si
	mov si, 0
	mov bh, 01h
	mov bl, 00h 
	mov ax, IPc 
	div bx   
  
	mov ch, dl
	mov cl, al
    
    mov ah, 0
	mov bl, 10h
	div bl 
  
	mov IPs, ah
	call Tikrina_IP   
	mov al, IPs
	call Tikrina_IP
  
	mov al, ch
	mov ah, 0
	div bl

	mov IPv, ah 
	call Tikrina_IP
	mov al, IPv
	call Tikrina_IP
	
	mov cx, 4														;cx - kiek baitu norima irasyti
	mov ah, 40h													;40h - rasymas i faila 
	mov bx, rezHandle											;failo deskriptorius (handleris)
	lea dx, bufIP													;load effective address , dx - rasymo buferio adresas
	int 21h 

	pop si
	ret
print_Ip endp

print_double proc
	push si
	mov si, 0
	mov bh, 01h
	mov bl, 00h 
	mov ah, poslv 
	mov al, poslj
	add ax, IPc 
	div bx   
  
	mov ch, dl
	mov cl, al
    
    mov ah, 0
	mov bl, 10h
	div bl 
  
	mov IPs, ah
	call Tikrina_IP   
	mov al, IPs
	call Tikrina_IP
  
	mov al, ch
	mov ah, 0
	div bl

	mov IPv, ah 
	call Tikrina_IP
	mov al, IPv
	call Tikrina_IP
	
	mov cx, 4														;cx - kiek baitu norima irasyti
	mov ah, 40h													;40h - rasymas i faila 
	mov bx, rezHandle											;failo deskriptorius (handleris)
	lea dx, bufIP													;load effective address , dx - rasymo buferio adresas
	int 21h 

	pop si
	ret
	
print_double endp
;------------------------------------------------------MASININIS KODAS----------------------------------------------------------------------; 

print_Masininis proc
	push si 
	push di
	mov di, 0
	mov si, 0 
	mov cx, kiekBaitu
__Veiksmas:
	mov al, [masKodas+di] 
	mov ah, 0
	mov bl, 10h
	div bl
	call print_ASCII
	mov [bufMAS+si], al
	inc si
	mov al, ah
	call print_ASCII
	mov [bufMAS+si], al	
	inc si
	inc di
	loop __Veiksmas
	
	mov cx, 13													;cx - kiek baitu norima irasyti
	mov ah, 40h													;40h - rasymas i faila 
	mov bx, rezHandle											;failo deskriptorius (handleris)
	lea dx, bufMAS													;load effective address , dx - rasymo buferio adresas
	int 21h 
	
	lea dx, tarpas
	call print_Simbolis
	
	pop di
	pop si
	ret
print_Masininis endp
;------------------------------------------------------KOMANDOS PAVADINIMAS--------------------------------------------------------------------;
print_Komanda proc
	mov cx, 5												;cx - kiek baitu norima irasyti
	mov ah, 40h												;40h - rasymas i faila 
	mov bx, rezHandle											;failo deskriptorius (handleris)
	mov dx, temp												;load effective address , dx - 
	int 21h 
	ret
print_Komanda endp
;-----------------------------------------------POSLINKIO JAUNESNYSIS BAITAS-------------------------------------------------------------------------------------------;
print_Poslinkis_j proc
	mov bl, 10h
	mov al, poslj
	div bl
	call print_ASCII
	mov [BufBetOp+0], al
	mov al, ah
	call print_ASCII
	mov [BufBetOp+1], al
	mov cx, 2
	mov ah, 40h
	mov bx, rezHandle
	lea dx, BufBetOp
	int 21h
	ret
print_Poslinkis_j endp
;------------------------------------------------------POSLINKIO VYRESNYSIS BAITAS------------------------------------------------------------------;
print_Poslinkis_v proc
	mov bl, 10h
	mov al, poslv
	div bl
	call print_ASCII
	mov [BufBetOp+0], al
	mov al, ah
	call print_ASCII
	mov [BufBetOp+1], al
	mov cx, 2
	mov ah, 40h
	mov bx, rezHandle
	lea dx, BufBetOp
	int 21h
	ret
print_Poslinkis_v endp
;------------------------------------------------------PIRMASIS OPERANDAS------------------------------------------------------------------;
print_Operandas1 proc
	mov cx, kiekSp 												
	mov ah, 40h												
	mov bx, rezHandle																							
	int 21h 
	ret
print_Operandas1 endp
;--------------------------------------------------------------------------------------------------------------------------------------------------;
print_byte_ptr proc
	mov cx, 9
	mov ah, 40h												
	mov bx, rezHandle																							
	int 21h 
	ret
print_byte_ptr endp
;------------------------------------------------------BETARPISKO OPERANDO JAUNESNYSIS BAITAS------------------------------------------------------------------;
print_BetOpjb proc
	mov al, BetOpjb
	mov bl, 10h
	div bl
	call print_ASCII
	mov [BufBetOp+0], al
	mov al, ah
	call print_ASCII
	mov [BufBetOp+1], al
	mov cx, 2
	mov ah, 40h
	mov bx, rezHandle
	lea dx, BufBetOp
	int 21h
	ret
print_BetOpjb endp
;------------------------------------------------------BETARPISKO OPERANDO VYRESNYSIS BAITAS------------------------------------------------------------------;
print_BetOpvb proc
	mov al, BetOpvb
	mov ah, 0
	mov bl, 10h
	div bl
	call print_ASCII
	mov [BufBetOp+0], al
	mov al, ah
	call print_ASCII
	mov [BufBetOp+1], al
	mov cx, 2
	mov ah, 40h
	mov bx, rezHandle
	lea dx, BufBetOp
	int 21h
	ret
print_BetOpvb endp
;------------------------------------------------------TAM TIKRAS SIMBOLIS------------------------------------------------------------------;
print_Simbolis proc
	mov cx, 1												;cx - kiek baitu norima irasyti
	mov ah, 40h												;40h - rasymas i faila 
	mov bx, rezHandle											;failo deskriptorius (handleris)
	int 21h 
	ret
print_Simbolis endp
;----------------------------------------------------ASCII----------------------------------------------------;
print_ASCII proc
	cmp al, 09h
	ja __Raide
	jmp __Skaicius
__Raide:
	add al, 37h  
	ret
__Skaicius:
	add al, 30h
	ret
print_ASCII endp

;----------------------------------------------------------------------------------------------------------------------------------------;
;----------------------------------------------------OPK TIKRINIMAS------------------------------------------------------------------;
;----------------------------------------------------------------------------------------------------------------------------------------;
recognizeOp proc
__Tag1:	
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 11110110b
	je __MulDivNot
	jmp __Tag2
__MulDivNot:
	call MulDivNot
	ret
	
__Tag2:
	mov dl, bufByte
	cmp dl, 11100010b
	je __Loop
	jmp __Tag3	
__Loop:
	mov [masKodas+0], dl
	inc kiekBaitu
	lea ax, opLOOP
	mov temp, ax
	call Loopas
	ret
	
__Tag3:
	mov dl, bufByte	
	cmp dl, 11001101b
	je __Int
	jmp __Tag4	
__Int:
	mov [masKodas+0], dl
	inc kiekBaitu
	lea ax, opINT
	mov temp, ax
	call Intas
	ret
	
__Tag4:																				
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 11111110b
	je __IncDecPushJmpCall
	jmp __Tag5
__IncDecPushJmpCall:
	call IncDecPushJmpCall
	ret

__Tag5:
	mov dl, bufByte
	and dl, 11110000b
	cmp dl, 01110000b
	je __CondJump
	jmp __Tag6
__CondJump:
	call CondJump
	ret
	
__Tag6:
	mov dl, bufByte
	cmp dl, 11100011b
	je __Jcxzas
	jmp __Tag7
__Jcxzas:
	mov [masKodas+0], dl
	inc kiekBaitu
	lea ax, opJCXZ
	mov temp, ax
	call Jcxzas
	ret

__Tag7:
	mov dl, bufByte
	and dl, 11111000b
	cmp dl, 01000000b
	je __Inc1
	jmp __Tag8
__Inc1:
	lea ax, opINC
	mov temp, ax
	call Inc1
	ret

__Tag8:
	mov dl, bufByte
	and dl, 11111000b
	cmp dl, 01001000b
	je __Dec1
	jmp __Tag9
__Dec1:
	lea ax, opDEC
	mov temp, ax
	call Dec1
	ret

__Tag9:
	mov dl, bufByte
	and dl, 11100111b
	cmp dl, 00000110b
	je __Push1
	jmp __Tag10
__Push1:
	lea ax, opPUSH
	mov temp, ax
	call Push1
	ret
	
__Tag10:
	mov dl, bufByte
	and dl, 11111000b
	cmp dl, 01010000b
	je __Push2
	jmp __Tag11
__Push2:
	lea ax, opPUSH
	mov temp, ax
	call Push2
	ret
	
__Tag11:
	mov dl, bufByte
	and dl, 11100111b
	cmp dl, 00000111b
	je __Pop1
	jmp __Tag12
__Pop1:
	lea ax, opPOP
	mov temp, ax
	call Pop1
	ret
	
__Tag12:
	mov dl, bufByte
	and dl, 11111000b
	cmp dl, 01011000b
	je __Pop2
	jmp __Tag13
__Pop2:
	lea ax, opPOP
	mov temp, ax
	call Pop2	
	ret
	
__Tag13:
	mov dl, bufByte
	cmp dl, 10001111b
	je __Pop3
	jmp __Tag14
__Pop3:
	lea ax, opPOP
	mov temp, ax
	call Pop3
	ret
	
__Tag14:
	mov dl, bufByte
	and dl, 11111100b
	cmp dl, 00000000b
	je __Add1
	jmp __Tag15
__Add1:
	lea ax, opADD
	mov temp, ax
	call Add1
	ret

__Tag15:
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 00000100b
	je __Add2
	jmp __Tag16
__Add2:
	lea ax, opADD
	mov temp, ax
	call Add2
	ret

__Tag16:
	mov dl, bufByte
	and dl, 11111100b
	cmp dl, 10000000b
	je __AddSubCmp
	jmp __Tag17
__AddSubCmp:
	call AddSubCmp
	ret

__Tag17:
	mov dl, bufByte
	and dl, 11111100b
	cmp dl, 00101000b
	je __Sub1
	jmp __Tag18
__Sub1:
	lea ax, opSUB
	mov temp, ax
	call Sub1
	ret

__Tag18:
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 00101100b
	je __Sub2
	jmp __Tag19
__Sub2:
	lea ax, opSUB
	mov temp, ax
	call Sub2
	ret

__Tag19:
	mov dl, bufByte
	and dl, 11111100b
	cmp dl, 00111000b
	je __Cmp1
	jmp __Tag20
__Cmp1:
	lea ax, opCMP
	mov temp, ax
	call Cmp1	
	ret
	
__Tag20:
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 00111100b
	je __Cmp2
	jmp __Tag21
__Cmp2:
	lea ax, opCMP
	mov temp, ax
	call Cmp2	
	ret
	
__Tag21:
	mov dl, bufByte
	and dl, 11110110b
	cmp dl, 11000010b
	je __Ret
	jmp __Tag22
__Ret:
	lea ax, opRET
	mov temp, ax
	call Retas	
	ret
	
__Tag22:
	mov dl, bufByte
	cmp dl, 11101000b
	je __Call1
	jmp __Tag23
__Call1:
	lea ax, opCALL
	mov temp, ax
	call Call1
	ret
	
__Tag23:
	mov dl, bufByte
	cmp dl, 10011010b
	je __Call2
	jmp __Tag24
__Call2:
	lea ax, opCALL
	mov temp, ax
	call Call2
	ret
	
__Tag24:
	mov dl, bufByte
	cmp dl, 11101011b
	je __Jmp1
	jmp __Tag25
__Jmp1:
	lea ax, opJMP
	mov temp, ax
	call Jmp1
	ret
	
__Tag25:
	mov dl, bufByte
	cmp dl, 11101001b
	je __Jmp2
	jmp __Tag26
__Jmp2:
	lea ax, opJMP
	mov temp, ax
	call Jmp2
	ret
	
__Tag26:
	mov dl, bufByte
	cmp dl, 11101010b
	je __Jmp3
	jmp __Tag27
__Jmp3:
	lea ax, opJMP
	mov temp, ax
	call Jmp3
	ret
	
__Tag27:
	mov dl, bufByte
	and dl, 11111100b
	cmp dl, 10001000b
	je __Mov1
	jmp __Tag28
__Mov1:
	lea ax, opMOV
	mov temp, ax
	call Mov1
	ret
	
__Tag28:
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 11000110b
	je __Mov2
	jmp __Tag29
__Mov2:
	lea ax, opMOV
	mov temp, ax
	call Mov2
	ret
	
__Tag29:
	mov dl, bufByte
	and dl, 11110000b
	cmp dl, 10110000b
	je __Mov3
	jmp __Tag30
__Mov3:
	lea ax, opMOV
	mov temp, ax
	call Mov3
	ret
	
__Tag30:
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 10100000b
	je __Mov4
	jmp __Tag31
__Mov4:
	lea ax, opMOV
	mov temp, ax
	call Mov4	
	ret
	
__Tag31:
	mov dl, bufByte
	and dl, 11111110b
	cmp dl, 10100010b
	je __Mov5
	jmp __Tag32
__Mov5:
	lea ax, opMOV
	mov temp, ax
	call Mov5
	ret
	
__Tag32:
	mov dl, bufByte
	and dl, 11111101b
	cmp dl, 10001100b
	je __Mov6
	jmp __Tag33
__Mov6:
	lea ax, opMOV
	mov temp, ax
	call Mov6	
	ret
	
__Tag33:
	call print_Neatpazinta
	call print_Enteris
	ret
recognizeOp endp	
;----------------------------------------------------AR PREFIKSAS--------------------------------------------------------------------------;	

arPrefix proc
	and dl, 11100111b
	cmp dl, 00100110b
	je __PrefixYes
	jmp __PrefixNo	
__PrefixYes:
	mov prefix, 1
	mov dl, bufByte
	mov prefixType, dl
	ret
__PrefixNo:
	mov prefix, 0
	mov dl, bufByte
	ret	
arPrefix endp
;---------------------------------- W = 0  YRA 1 BAITO BETARPISKAS OPERANDAS-------------------------------------------------------------------------------;
W0BetOp1 proc
	call readByte
	mov dh, 0
    mov dl, bufByte 
	mov [masKodas+1], dl
	inc kiekBaitu
	mov BetOpjb, dl
	call print_Masininis
	call print_Komanda
	lea dx, rb_000
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	call print_Enteris
	ret
W0BetOp1 endp
;---------------------------------- W = 1  YRA 2 BAITU BETARPISKAS OPERANDAS------------------------------------------------------------------------------------------------------;
W1BetOp2 proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov BetOpjb, dl
	call readByte
	mov dh, 0
    mov dl, bufByte 
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpvb, dl
	call print_Masininis
	call print_Komanda
	lea dx, rw_000
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	call print_Enteris
	ret
W1BetOp2 endp
;------------------------------------ D = 0  W = 0  R/M -> REG ---------------------------------------------------------------------;
D0W0RegRM proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call print_Masininis
	call print_Komanda
	and dl, 00111000b
	call W0TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB
	and dl, 00000111b
	call W0MOD11TikrinaRM
	call print_Enteris
	ret
D0W0RegRM endp
;------------------------------------ D = 0  W = 1  R/M -> REG ---------------------------------------------------------------------;
D0W1RegRM proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call print_Masininis
	call print_Komanda
	and dl, 00111000b
	call W1TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB
	and dl, 00000111b
	call W1MOD11TikrinaRM
	call print_Enteris
	ret
D0W1RegRM endp
;------------------------------------ D = 1  W = 0  REG -> R/M ---------------------------------------------------------------------;
D1W0RMReg proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call print_Masininis
	call print_Komanda
	and dl, 00000111b
	call W0MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB
	and dl, 00111000b
	call W0TikrinaReg
	call print_Enteris
	ret
D1W0RMReg endp
;------------------------------------ D = 1  W = 1  REG -> R/M ---------------------------------------------------------------------;
D1W1RMReg proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call print_Masininis
	call print_Komanda
	and dl, 00000111b
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB
	and dl, 00111000b
	call W1TikrinaReg
	call print_Enteris
	ret
D1W1RMReg endp
;----------------------------------- W = 1 TIKRINA REG DALI -----------------------------------------------------------------------;
W1TikrinaReg proc
	cmp dl, 00000000b
	je __W1Reg000
	cmp dl, 00001000b
	je __W1Reg001
	cmp dl, 00010000b
	je __W1Reg010
	cmp dl, 00011000b
	je __W1Reg011
	cmp dl, 00100000b
	je __W1Reg100
	cmp dl, 00101000b
	je __W1Reg101
	cmp dl, 00110000b
	je __W1Reg110
	cmp dl, 00111000b
	je __W1Reg111

__W1Reg000:
	lea dx, rw_000
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg001:
	lea dx, rw_001
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg010:
	lea dx, rw_010
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg011:
	lea dx, rw_011
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg100:
	lea dx, rw_100
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg101:
	lea dx, rw_101
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg110:
	lea dx, rw_110
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Reg111:
	lea dx, rw_111
	mov kiekSp, 2
	call print_Operandas1
	ret	
W1TikrinaReg endp
;----------------------------------- W = 0 TIKRINA REG DALI -----------------------------------------------------------------------;
W0TikrinaReg proc
	cmp dl, 00000000b
	je __W0Reg000
	cmp dl, 00001000b
	je __W0Reg001
	cmp dl, 00010000b
	je __W0Reg010
	cmp dl, 00011000b
	je __W0Reg011
	cmp dl, 00100000b
	je __W0Reg100
	cmp dl, 00101000b
	je __W0Reg101
	cmp dl, 00110000b
	je __W0Reg110
	cmp dl, 00111000b
	je __W0Reg111
__W0Reg000:
	lea dx, rb_000
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg001:
	lea dx, rb_001
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg010:
	lea dx, rb_010
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg011:
	lea dx, rb_011
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg100:
	lea dx, rb_100
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg101:
	lea dx, rb_101
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg110:
	lea dx, rb_110
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Reg111:
	lea dx, rb_111
	mov kiekSp, 2
	call print_Operandas1
	ret	
W0TikrinaReg endp
;----------------------------------- W = 0  MOD = 11 TIKRINA R/M DALI-----------------------------------------------------------------------;

W0MOD11TikrinaRM proc
	cmp dl, 00000000b
	je __W0Mod11RM000
	cmp dl, 00000001b
	je __W0Mod11RM001
	cmp dl, 00000010b
	je __W0Mod11RM010
	cmp dl, 00000011b
	je __W0Mod11RM011
	cmp dl, 00000100b
	je __W0Mod11RM100
	cmp dl, 00000101b
	je __W0Mod11RM101
	cmp dl, 00000110b
	je __W0Mod11RM110
	cmp dl, 00000111b
	je __W0Mod11RM111
__W0Mod11RM000:
	lea dx, rb_000
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM001:
	lea dx, rb_001
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM010:
	lea dx, rb_010
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM011:
	lea dx, rb_011
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM100:
	lea dx, rb_100
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM101:
	lea dx, rb_101
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM110:
	lea dx, rb_110
	mov kiekSp, 2
	call print_Operandas1
	ret
__W0Mod11RM111:
	lea dx, rb_111
	mov kiekSp, 2
	call print_Operandas1
	ret	
W0MOD11TikrinaRM endp
;----------------------------------------------------------------------------------------------------------------------------------------;
print_RM_Masyvas proc
	mov cx, 8
	lea dx, PrintRegMasyvas
	mov ah, 40h												
	mov bx, rezHandle																							
	int 21h 
	ret
print_RM_Masyvas endp


W10MODNe11TikrinaRM proc
	lea dx, skliaustas1
	call print_Simbolis
	mov dl, ADB
	and dl, 00000111b
	push si
	push di
	mov si, 0
	mov cx, 8
	mov al, 8
	mov ah, 0
	mul dl
	mov di, ax
__LoopMasininis:
	mov bl, [RegistruMasyvas+di]
	mov [PrintRegMasyvas+si], bl
	inc di
	inc si
	loop __LoopMasininis
	call print_RM_Masyvas
	pop di
	pop si
	ret
W10MODNe11TikrinaRM endp

;----------------------------------- W = 1  MOD = 11  TIKRINA R/M DALI-----------------------------------------------------------------------;
W1MOD11TikrinaRM proc
	cmp dl, 00000000b
	je __W1Mod11RM000
	cmp dl, 00000001b
	je __W1Mod11RM001
	cmp dl, 00000010b
	je __W1Mod11RM010
	cmp dl, 00000011b
	je __W1Mod11RM011
	cmp dl, 00000100b
	je __W1Mod11RM100
	cmp dl, 00000101b
	je __W1Mod11RM101
	cmp dl, 00000110b
	je __W1Mod11RM110
	cmp dl, 00000111b
	je __W1Mod11RM111
__W1Mod11RM000:
	lea dx, rw_000
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM001:
	lea dx, rw_001
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM010:
	lea dx, rw_010
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM011:
	lea dx, rw_011
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM100:
	lea dx, rw_100
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM101:
	lea dx, rw_101
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM110:
	lea dx, rw_110
	mov kiekSp, 2
	call print_Operandas1
	ret
__W1Mod11RM111:
	lea dx, rw_111
	mov kiekSp, 2
	call print_Operandas1
	ret	
W1MOD11TikrinaRM endp
;--------------------------------------------------------------------------------------------------------;
PaprMOD00TikrinaRM proc
	lea dx, skliaustas1
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	cmp dl, 00000000b
	je __PaprMod00RM000
	cmp dl, 00000001b
	je __PaprMod00RM001
	cmp dl, 00000010b
	je __PaprMod00RM010
	cmp dl, 00000011b
	je __PaprMod00RM011
	cmp dl, 00000100b
	je __PaprMod00RM100
	cmp dl, 00000101b
	je __PaprMod00RM101
	cmp dl, 00000110b
	je __PaprMod00RM110
	jmp __PaprMod00RM111	
__PaprMod00RM000:
	lea dx, rm_000
	mov kiekSp, 7
	call print_Operandas1
	ret
__PaprMod00RM001:
	lea dx, rm_001
	mov kiekSp, 7
	call print_Operandas1
	ret
__PaprMod00RM010:
	lea dx, rm_010
	mov kiekSp, 7
	call print_Operandas1
	ret
__PaprMod00RM011:
	lea dx, rm_011
	mov kiekSp, 7
	call print_Operandas1
	ret
__PaprMod00RM100:
	lea dx, rm_100
	mov kiekSp, 2
	call print_Operandas1
	ret
__PaprMod00RM101:
	lea dx, rm_101
	mov kiekSp, 2
	call print_Operandas1
	ret
__PaprMod00RM110:	
	call print_Poslinkis_v
	call print_Poslinkis_j
	ret
__PaprMod00RM111:
	lea dx, rm_111
	mov kiekSp, 2
	call print_Operandas1
	ret
PaprMOD00TikrinaRM endp
;--------------------------------------------------------------------------------------------------------;
W10MOD00TikrinaRM proc
	mov dl, ADB 
	and dl, 00000111b
	cmp dl, 00000000b
	je __W10Mod00RM000
	cmp dl, 00000001b
	je __W10Mod00RM001
	cmp dl, 00000010b
	je __W10Mod00RM010
	cmp dl, 00000011b
	je __W10Mod00RM011
	cmp dl, 00000100b
	je __W10Mod00RM100
	cmp dl, 00000101b
	je __W10Mod00RM101
	cmp dl, 00000110b
	je __W10Mod00RM110
	jmp __W10Mod00RM111	
__W10Mod00RM000:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_000
	mov kiekSp, 7
	call print_Operandas1
	ret
__W10Mod00RM001:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_001
	mov kiekSp, 7
	call print_Operandas1
	ret
__W10Mod00RM010:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_010
	mov kiekSp, 7
	call print_Operandas1
	ret
__W10Mod00RM011:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_011
	mov kiekSp, 7
	call print_Operandas1
	ret
__W10Mod00RM100:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_100
	mov kiekSp, 2
	call print_Operandas1
	ret
__W10Mod00RM101:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_101
	mov kiekSp, 2
	call print_Operandas1
	ret
__W10Mod00RM110:	
	lea dx, byte_ptr
	call print_byte_ptr
	lea dx, skliaustas1
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	ret
__W10Mod00RM111:
	lea dx, skliaustas1
	call print_Simbolis
	lea dx, rm_111
	mov kiekSp, 2
	call print_Operandas1
	ret
W10MOD00TikrinaRM endp
;--------------------------------------------------------------------------------------------------------;
ModRMPosl proc 
	mov dl, ADB
	and dl, 11000000b	
__ModRMPosl1:														
	cmp dl, 00000000b
	je __ModRMPoslMod00
	jmp __ModRMPosl2
__ModRMPoslMod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr1
	jmp __NeSkaitoMod110Nr1
__SkaitoMod110Nr1:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr1:				
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call PaprMOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	ret	
__ModRMPosl2:
	cmp dl, 01000000b
	je __ModRMPoslMod01
	jmp __ModRMPosl3
__ModRMPoslMod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ModRMPoslFF
	jmp __ModRMPosl00
__ModRMPoslFF:
	mov poslv, 255
	jmp ModRMPoslToliau
__ModRMPosl00:
	mov poslv, 00
	jmp ModRMPoslToliau
ModRMPoslToliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__ModRMPosl3:
	cmp dl, 10000000b
	je __ModRMPoslMod10
	jmp __ModRMPoslMod11
__ModRMPoslMod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__ModRMPoslMod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	ret
ModRMPosl endp
;---------------------------------------------------------------------------------------------;

DwModRegRMPosl proc 
	and dl, 00000011b
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__AddSubCmpMov1:														
	cmp dl, 00000000b
	je __AddSubCmpMovD0W0
	jmp __AddSubCmpMov2
__AddSubCmpMovD0W0:				
	call readByte
	mov dl, bufByte
	mov ADB, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	and dl, 11000000b
__ASCMd0w0Mod1:															
	cmp dl, 00000000b
	je __ASCMd0w0Mod00
	jmp __ASCMd0w0Mod2
__ASCMd0w0Mod00:
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr2
	jmp __NeSkaitoMod110Nr2
__SkaitoMod110Nr2:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr2:			
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call PaprMOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	ret	
__ASCMd0w0Mod2:
	cmp dl, 01000000b
	je __ASCMd0w0Mod01
	jmp __ASCMd0w0Mod3
__ASCMd0w0Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCMd0w0FF
	jmp __ASCMd0w000
__ASCMd0w0FF:
	mov poslv, 255
	jmp ASCMd0w0Toliau
__ASCMd0w000:
	mov poslv, 00
	jmp ASCMd0w0Toliau
ASCMd0w0Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	ret
__ASCMd0w0Mod3:
	cmp dl, 10000000b
	je __ASCMd0w0Mod10
	jmp __ASCMd0w0Mod11
__ASCMd0w0Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	ret
__ASCMd0w0Mod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__AddSubCmpMov2:
	cmp dl, 00000001b
	je __AddSubCmpMovD0W1
	jmp __AddSubCmpMov3
__AddSubCmpMovD0W1:
	call readByte
	mov dl, bufByte
	mov ADB, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	and dl, 11000000b
__ASCMd0w1Mod1:															
	cmp dl, 00000000b
	je __ASCMd0w1Mod00
	jmp __ASCMd0w1Mod2
__ASCMd0w1Mod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr3
	jmp __NeSkaitoMod110Nr3
__SkaitoMod110Nr3:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr3:			
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call PaprMOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	ret	
__ASCMd0w1Mod2:
	cmp dl, 01000000b
	je __ASCMd0w1Mod01
	jmp __ASCMd0w1Mod3
__ASCMd0w1Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCMd0w1FF
	jmp __ASCMd0w100
__ASCMd0w1FF:
	mov poslv, 255
	jmp ASCMd0w1Toliau
__ASCMd0w100:
	mov poslv, 00
	jmp ASCMd0w1Toliau
ASCMd0w1Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	ret
__ASCMd0w1Mod3:
	cmp dl, 10000000b
	je __ASCMd0w1Mod10
	jmp __ASCMd0w1Mod11
__ASCMd0w1Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	ret
__ASCMd0w1Mod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	ret	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__AddSubCmpMov3:
	cmp dl, 00000010b
	je __AddSubCmpMovD1W0
	jmp __AddSubCmpMov4
__AddSubCmpMovD1W0:
	call readByte
	mov dl, bufByte
	mov ADB, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	and dl, 11000000b
__ASCMd1w0Mod1:															
	cmp dl, 00000000b
	je __ASCMd1w0Mod00
	jmp __ASCMd1w0Mod2
__ASCMd1w0Mod00:
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr4
	jmp __NeSkaitoMod110Nr4
__SkaitoMod110Nr4:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr4:	
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call PaprMOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	ret	
__ASCMd1w0Mod2:
	cmp dl, 01000000b
	je __ASCMd1w0Mod01
	jmp __ASCMd1w0Mod3
__ASCMd1w0Mod01:				;1b poslinkis							;1.2
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCMd1w0FF
	jmp __ASCMd1w000
__ASCMd1w0FF:
	mov poslv, 255
	jmp ASCMd1w0Toliau
__ASCMd1w000:
	mov poslv, 00
	jmp ASCMd1w0Toliau
ASCMd1w0Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__ASCMd1w0Mod3:
	cmp dl, 10000000b
	je __ASCMd1w0Mod10
	jmp __ASCMd1w0Mod11
__ASCMd1w0Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__ASCMd1w0Mod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W0TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
__AddSubCmpMov4:
	cmp dl, 00000011b
	je __AddSubCmpMovD1W1
__AddSubCmpMovD1W1:
	call readByte
	mov dl, bufByte
	mov ADB, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	and dl, 11000000b
__ASCMd1w1Mod1:															
	cmp dl, 00000000b
	je __ASCMd1w1Mod00
	jmp __ASCMd1w1Mod2
__ASCMd1w1Mod00:
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr5
	jmp __NeSkaitoMod110Nr5
__SkaitoMod110Nr5:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr5:			
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	ret	
__ASCMd1w1Mod2:
	cmp dl, 01000000b
	je __ASCMd1w1Mod01
	jmp __ASCMd1w1Mod3
__ASCMd1w1Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCMd1w1FF
	jmp __ASCMd1w100
__ASCMd1w1FF:
	mov poslv, 255
	jmp ASCMd1w1Toliau
__ASCMd1w100:
	mov poslv, 00
	jmp ASCMd1w1Toliau
ASCMd1w1Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__ASCMd1w1Mod3:
	cmp dl, 10000000b
	je __ASCMd1w1Mod10
	jmp __ASCMd1w1Mod11
__ASCMd1w1Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__ASCMd1w1Mod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00111000b
	call W1TikrinaReg
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	mov dl, ADB 
	and dl, 00000111b
	call W1MOD11TikrinaRM
	ret	
DwModRegRMPosl endp	

WModRMPosl proc 
	mov dl, OPK
	and dl, 00000001b													
	cmp dl, 00000000b
	je __WModRMPoslW0
	jmp __WModRMPoslW1
__WModRMPoslW0:				
	mov dl, ADB
	and dl, 11000000b
__W0ModRMPoslMod1:															
	cmp dl, 00000000b
	je __W0ModRMPoslMod00
	jmp __W0ModRMPoslMod2
__W0ModRMPoslMod00:
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr6
	jmp __NeSkaitoMod110Nr6
__SkaitoMod110Nr6:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr6:							
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	ret	
__W0ModRMPoslMod2:
	cmp dl, 01000000b
	je __W0ModRMPoslMod01
	jmp __W0ModRMPoslMod3
__W0ModRMPoslMod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __W0ModRMPoslFF
	jmp __W0ModRMPosl00
__W0ModRMPoslFF:
	mov poslv, 255
	jmp __W0ModRMPoslToliau
__W0ModRMPosl00:
	mov poslv, 00
	jmp __W0ModRMPoslToliau
__W0ModRMPoslToliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__W0ModRMPoslMod3:
	cmp dl, 10000000b
	je __W0ModRMPoslMod10
	jmp __W0ModRMPoslMod11
__W0ModRMPoslMod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__W0ModRMPoslMod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__WModRMPoslW1:
	mov dl, ADB
	and dl, 11000000b
__W1ModRMPoslMod1:															
	cmp dl, 00000000b
	je __W1ModRMPoslMod00
	jmp __W1ModRMPoslMod2
__W1ModRMPoslMod00:		
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr7
	jmp __NeSkaitoMod110Nr7
__SkaitoMod110Nr7:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu					
__NeSkaitoMod110Nr7:					
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	ret	
__W1ModRMPoslMod2:
	cmp dl, 01000000b
	je __W1ModRMPoslMod01
	jmp __W1ModRMPoslMod3
__W1ModRMPoslMod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __W1ModRMPoslFF
	jmp __W1ModRMPosl00
__W1ModRMPoslFF:
	mov poslv, 255
	jmp __W1ModRMPoslToliau
__W1ModRMPosl00:
	mov poslv, 00
	jmp __W1ModRMPoslToliau
__W1ModRMPoslToliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__W1ModRMPoslMod3:
	cmp dl, 10000000b
	je __W1ModRMPoslMod10
	jmp __W1ModRMPoslMod11
__W1ModRMPoslMod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	ret
__W1ModRMPoslMod11:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W1MOD11TikrinaRM
	ret
WModRMPosl endp	
;----------------------------------------------------------------------------------------------------------------------------------------;
SwModRMPoslBetOp proc 
	mov dl, OPK
	and dl, 00000011b
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__AddSubCmp1:														
	cmp dl, 00000000b
	je __AddSubCmpS0W0
	jmp __AddSubCmp2
__AddSubCmpS0W0:				
	mov dl, ADB
	and dl, 11000000b
__ASCs0w0Mod1:															
	cmp dl, 00000000b
	je __ASCs0w0Mod00
	jmp __ASCs0w0Mod2
__ASCs0w0Mod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr8
	jmp __NeSkaitoMod110Nr8
__SkaitoMod110Nr8:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu	
	call readByte
    mov dl, bufByte
	mov [masKodas+4], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	jmp __toliau1
__NeSkaitoMod110Nr8:	
	call readByte
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpjb, dl	
__toliau1:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret	
__ASCs0w0Mod2:
	cmp dl, 01000000b
	je __ASCs0w0Mod01
	jmp __ASCs0w0Mod3
__ASCs0w0Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCs0w0FF
	jmp __ASCs0w000
__ASCs0w0FF:
	mov poslv, 255
	jmp ASCs0w0Toliau
__ASCs0w000:
	mov poslv, 00
	jmp ASCs0w0Toliau
ASCs0w0Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret
__ASCs0w0Mod3:
	cmp dl, 10000000b
	je __ASCs0w0Mod10
	jmp __ASCs0w0Mod11
__ASCs0w0Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret
__ASCs0w0Mod11:
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__AddSubCmp2:
	cmp dl, 00000001b
	je __AddSubCmpS0W1
	jmp __AddSubCmp3
__AddSubCmpS0W1:
	mov dl, ADB
	and dl, 11000000b
__ASCs0w1Mod1:															
	cmp dl, 00000000b
	je __ASCs0w1Mod00
	jmp __ASCs0w1Mod2
__ASCs0w1Mod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr9
	jmp __NeSkaitoMod110Nr9
__SkaitoMod110Nr9:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu	
	call readByte
    mov dl, bufByte
	mov [masKodas+4], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+5], dl
	inc kiekBaitu
	jmp __toliau2
__NeSkaitoMod110Nr9:	
	call readByte
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
__toliau2:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
__ASCs0w1Mod2:
	cmp dl, 01000000b
	je __ASCs0w1Mod01
	jmp __ASCs0w1Mod3
__ASCs0w1Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCs0w1FF
	jmp __ASCs0w100
__ASCs0w1FF:
	mov poslv, 255
	jmp ASCs0w1Toliau
__ASCs0w100:
	mov poslv, 00
	jmp ASCs0w1Toliau
ASCs0w1Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__ASCs0w1Mod3:
	cmp dl, 10000000b
	je __ASCs0w1Mod10
	jmp __ASCs0w1Mod11
__ASCs0w1Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+5], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__ASCs0w1Mod11:
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__AddSubCmp3:
	cmp dl, 00000010b
	je __AddSubCmpS1W0
	jmp __AddSubCmpS1W1
__AddSubCmpS1W0:
	mov dl, ADB
	and dl, 11000000b
__ASCs1w0Mod1:															
	cmp dl, 00000000b
	je __ASCs1w0Mod00
	jmp __ASCs1w0Mod2
__ASCs1w0Mod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr10
	jmp __NeSkaitoMod110Nr10
__SkaitoMod110Nr10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu	
	call readByte
    mov dl, bufByte
	mov [masKodas+4], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	jmp __toliau3
__NeSkaitoMod110Nr10:	
	call readByte
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpjb, dl	
__toliau3:
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w0Mod00FF
	jmp __ASCs1w0Mod0000
__ASCs1w0Mod00FF:
	mov BetOpvb, 255
	jmp __ASCs1w0Mod00Toliau
__ASCs1w0Mod0000:
	mov BetOpvb, 00
	jmp __ASCs1w0Mod00Toliau
__ASCs1w0Mod00Toliau:
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
__ASCs1w0Mod2:
	cmp dl, 01000000b
	je __ASCs1w0Mod01
	jmp __ASCs1w0Mod3
__ASCs1w0Mod01:				;1b poslinkis							;1.2
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w0Mod01FF
	jmp __ASCs1w0Mod0100
__ASCs1w0Mod01FF:
	mov BetOpvb, 255
	jmp __ASCs1w0Mod01Toliau
__ASCs1w0Mod0100:
	mov BetOpvb, 00
	jmp __ASCs1w0Mod01Toliau
__ASCs1w0Mod01Toliau:
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCs1w0FF
	jmp __ASCs1w000
__ASCs1w0FF:
	mov poslv, 255
	jmp ASCMd1w0Toliau
__ASCs1w000:
	mov poslv, 00
	jmp ASCs1w0Toliau
ASCs1w0Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__ASCs1w0Mod3:
	cmp dl, 10000000b
	je __ASCs1w0Mod10
	jmp __ASCs1w0Mod11
__ASCs1w0Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w0Mod10FF
	jmp __ASCs1w0Mod1000
__ASCs1w0Mod10FF:
	mov BetOpvb, 255
	jmp __ASCs1w0Mod10Toliau
__ASCs1w0Mod1000:
	mov BetOpvb, 00
	jmp __ASCs1w0Mod10Toliau
__ASCs1w0Mod10Toliau:
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__ASCs1w0Mod11:
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w0Mod11FF
	jmp __ASCs1w0Mod1100
__ASCs1w0Mod11FF:
	mov BetOpvb, 255
	jmp __ASCs1w0Mod11Toliau
__ASCs1w0Mod1100:
	mov BetOpvb, 00
	jmp __ASCs1w0Mod11Toliau
__ASCs1w0Mod11Toliau:
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

__AddSubCmpS1W1:
	mov dl, ADB
	and dl, 11000000b
__ASCs1w1Mod1:															
	cmp dl, 00000000b
	je __ASCs1w1Mod00
	jmp __ASCs1w1Mod2
__ASCs1w1Mod00:				
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr11
	jmp __NeSkaitoMod110Nr11
__SkaitoMod110Nr11:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu	
	call readByte
    mov dl, bufByte
	mov [masKodas+4], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	jmp __toliau4
__NeSkaitoMod110Nr11:	
	call readByte
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpjb, dl	
__toliau4:
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w1Mod00FF
	jmp __ASCs1w1Mod0000
__ASCs1w1Mod00FF:
	mov BetOpvb, 255
	jmp __ASCs1w1Mod00Toliau
__ASCs1w1Mod0000:
	mov BetOpvb, 00
	jmp __ASCs1w1Mod00Toliau
__ASCs1w1Mod00Toliau:
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
__ASCs1w1Mod2:
	cmp dl, 01000000b
	je __ASCs1w1Mod01
	jmp __ASCs1w1Mod3
__ASCs1w1Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w1Mod01FF
	jmp __ASCs1w1Mod0100
__ASCs1w1Mod01FF:
	mov BetOpvb, 255
	jmp __ASCs1w1Mod01Toliau
__ASCs1w1Mod0100:
	mov BetOpvb, 00
	jmp __ASCs1w1Mod01Toliau
__ASCs1w1Mod01Toliau:	
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __ASCs1w1FF
	jmp __ASCs1w100
__ASCs1w1FF:
	mov poslv, 255
	jmp ASCs1w1Toliau
__ASCs1w100:
	mov poslv, 00
	jmp ASCs1w1Toliau
ASCs1w1Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__ASCs1w1Mod3:
	cmp dl, 10000000b
	je __ASCs1w1Mod10
	jmp __ASCs1w1Mod11
__ASCs1w1Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w1Mod10FF
	jmp __ASCs1w1Mod1000
__ASCs1w1Mod10FF:
	mov BetOpvb, 255
	jmp __ASCs1w1Mod10Toliau
__ASCs1w1Mod1000:
	mov BetOpvb, 00
	jmp __ASCs1w1Mod10Toliau
__ASCs1w1Mod10Toliau:	
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__ASCs1w1Mod11:
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, BetOpjb
	and dl, 10000000b
	cmp dl, 10000000b
	je __ASCs1w1Mod11FF
	jmp __ASCs1w1Mod1100
__ASCs1w1Mod11FF:
	mov BetOpvb, 255
	jmp __ASCs1w1Mod11Toliau
__ASCs1w1Mod1100:
	mov BetOpvb, 00
	jmp __ASCs1w1Mod11Toliau
__ASCs1w1Mod11Toliau:	
	mov dl, ADB 
	and dl, 00000111b
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
SwModRMPoslBetOp endp
;----------------------------------------------------------------------------------------------------------------------------------------;
wModRMPoslBetOp proc 
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov ADB, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	mov dl, OPK
	and dl, 00000001b
													
	cmp dl, 00000000b
	je __MovW0
	jmp __MovW1
__MovW0:				
	mov dl, ADB
	and dl, 11000000b
__MovW0Mod1:															
	cmp dl, 00000000b
	je __MovW0Mod00
	jmp __MovW0Mod2
__MovW0Mod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr12
	jmp __NeSkaitoMod110Nr12
__SkaitoMod110Nr12:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu	
	call readByte
    mov dl, bufByte
	mov [masKodas+4], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	jmp __toliau5
__NeSkaitoMod110Nr12:	
	call readByte
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpjb, dl	
__toliau5:	
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret	
__MovW0Mod2:
	cmp dl, 01000000b
	je __MovW0Mod01
	jmp __MovW0Mod3
__MovW0Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __MovW0FF
	jmp __MovW000
__MovW0FF:
	mov poslv, 255
	jmp MovW0Toliau
__MovW000:
	mov poslv, 00
	jmp MovW0Toliau
MovW0Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret
__MovW0Mod3:
	cmp dl, 10000000b
	je __MovW0Mod10
	jmp __MovW0Mod11
__MovW0Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret
__MovW0Mod11:
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W0MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
__MovW1:
	mov dl, ADB
	and dl, 11000000b
__MovW1Mod1:															
	cmp dl, 00000000b
	je __MovW1Mod00
	jmp __MovW1Mod2
__MovW1Mod00:	
	mov dl, ADB
	and dl, 00000111b
	cmp dl, 00000110b
	je __SkaitoMod110Nr13
	jmp __NeSkaitoMod110Nr13
__SkaitoMod110Nr13:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu	
	call readByte
    mov dl, bufByte
	mov [masKodas+4], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+5], dl
	inc kiekBaitu
	jmp __toliau6
__NeSkaitoMod110Nr13:	
	call readByte
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpjb, dl	
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
__toliau6:
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MOD00TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
__MovW1Mod2:
	cmp dl, 01000000b
	je __MovW1Mod01
	jmp __MovW1Mod3
__MovW1Mod01:				
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	mov dl, poslj
	and dl, 10000000b
	je __MovW1FF
	jmp __MovW100
__MovW1FF:
	mov poslv, 255
	jmp __MovW1Toliau
__MovW100:
	mov poslv, 00
	jmp __MovW1Toliau
__MovW1Toliau:
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__MovW1Mod3:
	cmp dl, 10000000b
	je __MovW1Mod10
	jmp __MovW1Mod11
__MovW1Mod10:
	call readByte
	mov dl, bufByte
	mov poslj, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov poslv, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+4], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+5], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W10MODNe11TikrinaRM
	lea dx, pliusas
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret
__MovW1Mod11:
	call readByte
	mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, ADB 
	and dl, 00000111b
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	ret	
wModRMPoslBetOp endp		
;----------------------------------------------------------------------------------------------------------------------------------------;
;-----------------------------------------------------KOMANDU ATPAZINIMAS-------------------------------------------------------------;
;----------------------------------------------------------------------------------------------------------------------------------------;

;---------------------------------------AR MUL AR DIV--------------------------------------------------------------------------------------------;
MulDivNot proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	mov OPK, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	and dl, 00111000b
	cmp dl, 00100000b
	je __Mul
	cmp dl, 00110000b
	je __Div
	cmp dl, 00010000b
	je __Not
	call print_Neatpazinta
	call print_Enteris
	ret
__Mul:
	call Mulas
	ret
__Div:
	call Divas	
	ret
__Not:
	call Notas
	ret
MulDivNot endp
;--------------------------------------MUL-----------------------------------------------------------------------------------------------;
Mulas proc
	lea ax, opMUL
	mov temp, ax
	call WModRMPosl
	call print_Enteris
	ret
Mulas endp
;--------------------------------------DIV-----------------------------------------------------------------------------------------------;
Divas proc
	lea ax, opDIV
	mov temp, ax
	call WModRMPosl
	call print_Enteris
	ret
Divas endp
;--------------------------------------NOT-----------------------------------------------------------------------------------------------;
Notas proc
	lea ax, opNOT
	mov temp, ax
	call WModRMPosl
	call print_Enteris
	ret
Notas endp
;--------------------------------------LOOP----------------------------------------------------------------------------------------------;
Loopas proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	
	call print_Masininis
	call print_Komanda
	call print_Poslinkis_j
	call print_Enteris
	ret
Loopas endp
;--------------------------------------INT-----------------------------------------------------------------------------------------------;
Intas proc
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	
	call print_Masininis
	call print_Komanda
	call print_Poslinkis_j
	call print_Enteris
	ret
Intas endp

IncDecPushJmpCall proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	mov OPK, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	
	and dl, 00111000b
	
	cmp dl, 00000000b
	je __Incas
	cmp dl, 00001000b
	je __Dacas
	cmp dl, 00010000b
	je __Callas1
	cmp dl, 00011000b
	je __Callas2
	cmp dl, 00100000b
	je __Jumpas1
	cmp dl, 00101000b
	je __Jumpas2
	cmp dl, 00110000b
	je __Pushas
	call print_Neatpazinta
	call print_Enteris
	ret
__Incas:
	lea ax, opINC
	mov temp, ax
	call Inc2
	ret
__Dacas:
	lea ax, opDEC
	mov temp, ax
	call Dec2
	ret
__Callas1:
	lea ax, opCALL
	mov temp, ax
	call Call3
	ret
__Callas2:
	lea ax, opCALL
	mov temp, ax
	call Call4
	ret
__Jumpas1:
	lea ax, opJMP
	mov temp, ax
	call Jmp4
	ret
__Jumpas2:
	lea ax, opJMP
	mov temp, ax
	call Jmp5
	ret
__Pushas:
	lea ax, opPUSH
	mov temp, ax
	call Push3
	ret
IncDecPushJmpCall endp

Inc2 proc
	call WModRMPosl
	call print_Enteris
	ret
Inc2 endp

Dec2 proc
	call WModRMPosl
	call print_Enteris
	ret
Dec2 endp

Call3 proc
	call ModRMPosl
	call print_Enteris	
	ret
Call3 endp

Call4 proc
	call ModRMPosl
	call print_Enteris	
	ret
Call4 endp

Jmp4 proc
	call ModRMPosl
	call print_Enteris	
	ret
Jmp4 endp

Jmp5 proc
	call ModRMPosl
	call print_Enteris	
	ret
Jmp5 endp

Push3 proc
	call ModRMPosl
	call print_Enteris	
	ret
Push3 endp

CondJump proc
	mov dl, bufByte
	mov OPK, dl
	mov [masKodas+0], dl
	inc kiekBaitu	
	call readByte
	mov [masKodas+1], al
	inc kiekBaitu	
	and al, 10000000b
	cmp al, 10000000b
	je __PleciamIPFF
	jmp __PleciamIP00
__PleciamIPFF:
	mov ah, 255
	jmp __PleciamIPToliau
__PleciamIP00:
	mov ah, 0
	jmp __PleciamIPToliau
__PleciamIPToliau:
    mov al, bufByte
	add ax, IPc
	mov poslj, al
	mov poslv, ah
	call print_Masininis
	mov dl, OPK
	and dl, 00001111b

__Salyga1:	
	cmp dl, 00000000b
	je __Jo
	jmp __Salyga2
__Jo:
	lea ax, opJO
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga2:
	cmp dl, 00000001b
	je __Jno
	jmp __Salyga3
__Jno:
	lea ax, opJNO
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga3:
	cmp dl, 00000010b
	je __Jnae
	jmp __Salyga4
__Jnae:
	lea ax, opJNAE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga4:	
	cmp dl, 00000011b
	je __Jae
	jmp __Salyga5
__Jae:
	lea ax, opJAE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga5:
	cmp dl, 00000100b
	je __Je
	jmp __Salyga6
__Je:
	lea ax, opJE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga6:
	cmp dl, 00000101b
	je __Jne
	jmp __Salyga7
__Jne:
	lea ax, opJNE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga7:
	cmp dl, 00000110b
	je __Jbe
	jmp __Salyga8
__Jbe:
	lea ax, opJBE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga8:
	cmp dl, 00000111b
	je __Ja
	jmp __Salyga9
__Ja:
	lea ax, opJA
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga9:
	cmp dl, 00001000b
	je __Js
	jmp __Salyga10
__Js:
	lea ax, opJS
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga10:
	cmp dl, 00001001b
	je __Jns
	jmp __Salyga11
__Jns:
	lea ax, opJNS
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga11:
	cmp dl, 00001010b
	je __Jp
	jmp __Salyga12
__Jp:
	lea ax, opJP
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga12:
	cmp dl, 00001011b
	je __Jnp
	jmp __Salyga13
__Jnp:
	lea ax, opJNP
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga13:
	cmp dl, 00001100b
	je __Jl
	jmp __Salyga14
__Jl:
	lea ax, opJL
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga14:
	cmp dl, 00001101b
	je __Jge
	jmp __Salyga15
__Jge:
	lea ax, opJGE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga15:
	cmp dl, 00001110b
	je __Jle
	jmp __Salyga16
__Jle:
	lea ax, opJLE
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
__Salyga16:
	cmp dl, 00001111b
	je __Jg
	call print_Neatpazinta
	call print_Enteris
	ret
__Jg:
	lea ax, opJG
	mov temp, ax
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j	
	call print_Enteris
	ret
CondJump endp

Jcxzas proc
	call readByte
	mov ah, 0
    mov al, bufByte
	add ax, IPc
	mov poslv, ah
	mov poslj, al
	mov [masKodas+1], al
	inc kiekBaitu

	call print_Masininis
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris	
	ret
Jcxzas endp

Inc1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, bufByte
	and dl, 00000111b
	call W1MOD11TikrinaRM
	call print_Enteris
	ret
Inc1 endp

Dec1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, bufByte
	and dl, 00000111b
	call W1MOD11TikrinaRM
	call print_Enteris
	ret
Dec1 endp

Push1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	and dl, 00011000b
	
	cmp dl, 00000000b
	je __PushES
	cmp dl, 00001000b
	je __PushCS
	cmp dl, 00010000b
	je __PushSS
	cmp dl, 00011000b
	je __PushDS
__PushES:
	lea dx, s_regES
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret	
__PushCS:
	lea dx, s_regCS
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret
__PushSS:
	lea dx, s_regSS
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret
__PushDS:
	lea dx, s_regDS
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret
Push1 endp

Push2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	mov OPK, dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	mov dl, OPK
	and dl, 00000111b
	call W1MOD11TikrinaRM
	call print_Enteris
	ret
Push2 endp

Pop1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	and dl, 00011000b
	
	cmp dl, 00000000b
	je __PopES
	cmp dl, 00001000b
	je __PopCS
	cmp dl, 00010000b
	je __PopSS
	cmp dl, 00011000b
	je __PopDS
__PopES:
	lea dx, s_regES
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret	
__PopCS:
	call print_Neatpazinta
	call print_Enteris
	ret
__PopSS:
	lea dx, s_regSS
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret
__PopDS:
	lea dx, s_regDS
	mov kiekSp, 2
	call print_Operandas1
	call print_Enteris
	ret
Pop1 endp

Pop2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	and dl, 00000111b
	call W1MOD11TikrinaRM
	call print_Enteris
	ret
Pop2 endp

Pop3 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call ModRMPosl
	call print_Enteris	
	ret
Pop3 endp

Add1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call DwModRegRMPosl
	call print_Enteris
	ret
Add1 endp

Add2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00000001b
	
	cmp dl, 00000001b
	je __Add2W1
	cmp dl, 00000000b
	je __Add2W0
__Add2W1:
	call W1BetOp2
	ret
__Add2W0:
	call W0BetOp1
	ret
Add2 endp

AddSubCmp proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	mov OPK, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	and dl, 00111000b
	
	cmp dl, 00000000b
	je __Add3
	cmp dl, 00101000b
	je __Sub3
	cmp dl, 00111000b
	je __Cmp3
	call print_Neatpazinta
	call print_Enteris
	ret
__Add3:
	lea ax, opADD
	mov temp, ax
	call Add3
	ret
__Sub3:
	lea ax, opSUB
	mov temp, ax
	call Sub3
	ret
__Cmp3:
	lea ax, opCMP
	mov temp, ax
	call Cmp3
	ret
AddSubCmp endp

Add3 proc
	call SwModRMPoslBetOp
	call print_Enteris
	ret
Add3 endp

Sub3 proc
	call SwModRMPoslBetOp
	call print_Enteris
	ret
Sub3 endp

Cmp3 proc
	call SwModRMPoslBetOp
	call print_Enteris
	ret
Cmp3 endp

Sub1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call DwModRegRMPosl
	call print_Enteris
	ret
Sub1 endp

Sub2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00000001b
	
	cmp dl, 00000001b
	je __Sub2W1
	cmp dl, 00000000b
	je __Sub2W0
__Sub2W1:
	call W1BetOp2
	ret
__Sub2W0:
	call W0BetOp1
	ret
Sub2 endp

Cmp1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call DwModRegRMPosl
	call print_Enteris
	ret
Cmp1 endp

Cmp2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00000001b
	
	cmp dl, 00000001b
	je __Cmp2W1
	cmp dl, 00000000b
	je __Cmp2W0
__Cmp2W1:
	call W1BetOp2
	ret
__Cmp2W0:
	call W0BetOp1
	ret
Cmp2 endp
;----------------------------------------------------------RET---------------------------------------------------------------;
Retas proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00001001b
	
	cmp dl, 00000001b
	je __VidinisBeSteko
	cmp dl, 00000000b
	je __VidinisSuSteko
	cmp dl, 00001001b
	je __IsorinisBeSteko
	cmp dl, 00001000b
	je __IsorinisSuSteko
__VidinisBeSteko:
	call print_Masininis
	call print_Komanda
	call print_Enteris
	ret
__VidinisSuSteko:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	call print_BetOpvb
	call print_BetOpjb
	call print_Enteris
	ret
__IsorinisBeSteko:
	call print_Masininis
	call print_Komanda
	call print_Enteris
	ret
__IsorinisSuSteko:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	call print_BetOpvb
	call print_BetOpjb
	call print_Enteris
	ret
Retas endp
;---------------------------------------------------CALL VIDINIS TIESIOGINIS--------------------------------------------------------------;
Call1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslv, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris
	ret
Call1 endp
;---------------------------------------------------CALL ISORINIS TIESIOGINIS-----------------------------------------------------------------------;
Call2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslv, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+4], dl
	inc kiekBaitu

	call print_Masininis
	call print_Komanda
	lea dx, skliaustas1
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	lea dx, dvitaskis
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	call print_Enteris
	ret
Call2 endp
;----------------------------------------------------JMP VIDINIS ARTIMAS----------------------------------------------------------------;
Jmp1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu	
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	and dl, 10000000b 
	cmp dl, 10000000b
	je __JmpFF
	jmp __Jmp00
__JmpFF:
	inc kiekBaitu
	jmp __JmpToliau
__Jmp00:
	inc kiekBaitu
	jmp __JmpToliau
__JmpToliau:
	call print_Masininis
	call print_Komanda
	call print_poslinkis_v
	call print_poslinkis_j
	call print_Enteris
	ret
Jmp1 endp
;---------------------------------------------------JMP VIDINIS TIESIOGINIS-------------------------------------------------------------------------;
Jmp2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu	
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl 
	mov [masKodas+1], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslv, dl 
	mov [masKodas+2], dl
	inc kiekBaitu
	call print_Masininis
	call print_Komanda
	call print_Poslinkis_v
	call print_Poslinkis_j
	call print_Enteris	
	ret
Jmp2 endp
;---------------------------------------------------JMP ISORINIS TIESIOGINIS----------------------------------------------------------------------;
Jmp3 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslj, dl
	mov [masKodas+1], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov poslv, dl
	mov [masKodas+2], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpjb, dl
	mov [masKodas+3], dl
	inc kiekBaitu
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov BetOpvb, dl
	mov [masKodas+4], dl
	inc kiekBaitu

	call print_Masininis
	call print_Komanda
	lea dx, skliaustas1
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	lea dx, dvitaskis
	call print_Simbolis
	call print_Poslinkis_v
	call print_Poslinkis_j
	lea dx, skliaustas2
	call print_Simbolis
	call print_Enteris
	ret
Jmp3 endp
;----------------------------------------------------MOV 1-------------------------------------------------------------------------;
Mov1 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call DwModRegRMPosl
	call print_Enteris
	ret
Mov1 endp
;-----------------------------------------------------MOV 2--------------------------------------------------------------------;
Mov2 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	call wModRMPoslBetOp
	call print_Enteris
	ret
Mov2 endp
;---------------------------------------------------------MOV 3-------------------------------------------------------------------;
Mov3 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00001000b
	cmp dl, 00001000b
	je __Mov3W1
	jmp __Mov3W0
	
__Mov3W1:
	mov dl, bufByte
	mov OPK, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov BetOpjb, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov BetOpvb, dl

	call print_Masininis
	call print_Komanda
	mov dl, OPK
	and dl, 00000111b
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	call print_Enteris
	ret
__Mov3W0:
	mov dl, bufByte
	mov OPK, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov BetOpjb, dl

	call print_Masininis
	call print_Komanda
	mov dl, OPK
	and dl, 00000111b
	call W0MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_BetOpjb
	call print_Enteris
	ret
Mov3 endp
;---------------------------------------------------------MOV 4----------------------------------------------------------------------;
Mov4 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00000001b
	cmp dl, 00000001b
	je __Mov4W1
	jmp	__Mov4W0
	
__Mov4W1:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov poslj, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov poslv, dl	
	call print_Masininis
	call print_Komanda
	lea dx, rw_000
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	lea dx, skliaustas1
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	lea dx, skliaustas2
	call print_Simbolis
	call print_Enteris
	ret
__Mov4W0:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov poslj, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov poslv, dl	
	call print_Masininis
	call print_Komanda
	lea dx, rb_000
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	lea dx, skliaustas1
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	lea dx, skliaustas2
	call print_Simbolis
	call print_Enteris
	ret
Mov4 endp
;---------------------------------------------------------MOV 5----------------------------------------------------------------------;
Mov5 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00000001b
	cmp dl, 00000001b
	je __Mov5W1
	jmp	__Mov5W0
	
__Mov5W1:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov poslj, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov poslv, dl	
	call print_Masininis
	call print_Komanda
	lea dx, rw_000
	mov kiekSp, 2
	lea dx, skliaustas1
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_Operandas1
	call print_Enteris
	ret
__Mov5W0:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov poslj, dl
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+2], dl
	inc kiekBaitu
	mov poslv, dl	
	call print_Masininis
	call print_Komanda
	mov kiekSp, 2
	lea dx, skliaustas1
	call print_Simbolis
	call print_BetOpvb
	call print_BetOpjb
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	lea dx, rb_000
	call print_Operandas1
	call print_Enteris
	ret
Mov5 endp
;----------------------------------------------------MOV 6----------------------------------------------------------------------------;
Mov6 proc
	mov dl, bufByte
	mov [masKodas+0], dl
	inc kiekBaitu
	and dl, 00000010b
	cmp dl, 00000010b
	je __Mov6D1
	jmp __Mov6D0
__Mov6D1:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call print_Masininis
	call print_Komanda
	
	and dl, 00011000b
	cmp dl, 00000000b
	je __Mov6D1ES
	cmp dl, 00001000b
	je __Mov6D1CS
	cmp dl, 00010000b
	je __Mov6D1SS
	cmp dl, 00011000b
	je __Mov6D1DS
__Mov6D1ES:
	lea dx, s_regES
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	jmp __Mov6D1Toliau
__Mov6D1CS:
	call print_Neatpazinta
	call print_Enteris
	ret
__Mov6D1SS:
	lea dx, s_regSS
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	jmp __Mov6D1Toliau
__Mov6D1DS:
	lea dx, s_regDS
	mov kiekSp, 2
	call print_Operandas1
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	jmp __Mov6D1Toliau
__Mov6D1Toliau:
	mov dl, ADB
	and dl, 11000000b
	cmp dl, 11000000b
	je __Mov6D1Mod11
	jmp __Mov6D1ModNe11
__Mov6D1Mod11:
	call W1MOD11TikrinaRM
	call print_Enteris
	ret
__Mov6D1ModNe11:
	lea dx, skliaustas1
	call print_Simbolis
	call W10MODNe11TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	call print_Enteris
	ret
	
__Mov6D0:
	call readByte
	mov dh, 0
    mov dl, bufByte
	mov [masKodas+1], dl
	inc kiekBaitu
	mov ADB, dl
	call print_Masininis
	call print_Komanda
	
	and dl, 00011000b
	cmp dl, 00000000b
	je __Mov6D0ES
	cmp dl, 00001000b
	je __Mov6D0CS
	cmp dl, 00010000b
	je __Mov6D0SS
	cmp dl, 00011000b
	je __Mov6D0DS
__Mov6D0ES:
	lea dx, s_regES
	mov kiekSp, 2
	jmp __Mov6D0Toliau
__Mov6D0CS:
	lea dx, s_regCS
	mov kiekSp, 2
	jmp __Mov6D0Toliau
__Mov6D0SS:
	lea dx, s_regSS
	mov kiekSp, 2
	jmp __Mov6D0Toliau
__Mov6D0DS:
	lea dx, s_regDS
	mov kiekSp, 2
	jmp __Mov6D0Toliau
__Mov6D0Toliau:
	mov dl, ADB
	and dl, 11000000b
	cmp dl, 11000000b
	je __Mov6D0Mod11
	jmp __Mov6D0ModNe11
__Mov6D0Mod11:
	call W1MOD11TikrinaRM
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_Operandas1
	call print_Enteris
	ret
__Mov6D0ModNe11:
	lea dx, skliaustas1
	call print_Simbolis
	call W10MODNe11TikrinaRM
	lea dx, skliaustas2
	call print_Simbolis
	lea dx, kablelis
	call print_Simbolis
	lea dx, tarpas
	call print_Simbolis
	call print_Operandas1
	call print_Enteris
	ret
Mov6 endp
	
end Programa		