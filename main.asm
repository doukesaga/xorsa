%include "./functions64.inc"						;library

;SECTION macros
%macro	setupFrame 0
		push 	rbp									;save existing main pointer
		mov 	rbp, rsp							;switch to local function pointer
%endmacro
%macro	closeFrame 0
		mov		rsp, rbp							;set pointer back
		pop		rbp									;restore pointer
%endmacro
%macro	file	4									;file	open, read, [rsp+16], 0, [inputFD]
		mov		rax, %1								;call value
		mov		rdx, %2								;access mode
		mov		rdi, %3								;address of file
		mov		rsi, %4								;file security flag: none				
		syscall										;call the kernel		
%endmacro
%macro	file	3									;file [inputFD], bytes, mode
		mov		rdi, %1								;file handler
		mov		rdx, %2								;bytes to write
		mov		rax, %3								;write mode						
		syscall										;call the kernel	
%endmacro
%macro	alloc	2
		mov		rdi, %1								;copy current limit
		add		rdi, %2								;size requested
		mov		rax, sys_brk						;sys_brk
		syscall										;rax now has new high limit.
%endmacro	
%macro	msg	1
		push	%1									;address of message
		call	PrintString							;print message
		call	Printendl							;print new line
%endmacro
%macro  saveRegisters 0
        push	rax
        push	rbx
        push	rcx
        push	rdx
		push	rsi
		push	rdi
		push	r8
		push	r9
		push	r10
		push	r11
		push	r12
		push	r13
		push	r14
		push	r15
%endmacro
%macro  restoreRegisters 0
		pop		r15
		pop		r14
		pop		r13
		pop		r12
		pop		r11
		pop		r10
		pop		r9
		pop		r8
        pop		rdi
        pop		rsi
        pop		rdx
        pop		rcx
		pop		rbx
		pop		rax
%endmacro


SECTION .data
	welcomeDisplay		db	"Welcome to my Program", 0h
	closeDisplay		db	"Program ending, have a nice day", 0h
	argError			db	"ERROR: two arguments required. ex: ./main sourcefile destfile", 0h
	sourceError			db  "ERROR: unable to open source file", 0h
	destError			db  "ERROR: unable to open destination file", 0h	
	readError			db  "ERROR: unable to read file", 0h
	writeError			db  "ERROR: unable to write file", 0h
	copyDisplay			db	"Coping source file to destination file", 0h
	keyPrompt	 		db  "Please enter a key for encrypting", 0h	
	bytesWritten		db	"Total bytes written", 0h
	QWORDSIZE			equ 8
	sys_read			equ 0
	sys_write			equ 1
	sys_create			equ 85
	sys_new				equ	0
	sys_open			equ 2
	sys_close			equ 3
	sys_brk				equ 0ch
	bufferSize			equ 0ffffh	

SECTION .bss
	inputFD				resq	1	
	outputFD			resq	1	
	originalBreak		resq	1
	userKey				resb	255
						.length equ($ - userKey)

SECTION .text
	global  _start

_start:
nop
    welcome:	msg		welcomeDisplay										;print message
    
	arguments:	cmp		QWORD[rsp], 3										;compare arguments
				je		input												;rsp < 3
				msg		argError											;display error
				jmp		exit												;exit function	
	
	input:		file	sys_open, sys_read, [rsp+16], 0						;syscall|mode|filename|permission macro
				cmp		rax, 0												;check return from kernel
				jge		inputOk												;rax < 0
				msg		sourceError											;display error
				jmp		exit												;exit function
	
	inputOk:	mov		[inputFD], rax										;ok to copy to file descriptor
	
	output:		file	sys_create, sys_new, [rsp+24], 0644o				;syscall|mode|filename|permission macro
				cmp		rax, 0												;check return from kernel
				jge		outputOk											;rax < 0	
				msg		destError											;display error
				jmp		exit												;exit function
	
	outputOk:	mov		[outputFD], rax										;ok to copy to file descriptor			
					
	getKey:		msg		keyPrompt											;prompt user for key
				push	userKey												;save characters from readText to here
				push	userKey.length										;max buffer size for readText
				call	ReadText											;get user input, (like cin in c++)
				dec 	rax													;skip enter
				mov		r9, rax												;save key length

	verbose:	msg		copyDisplay											;display message
	
	heap:		alloc	0, 0											;get current program memory address
				mov		[originalBreak], rax								;save address for deallocation
				mov		rsi, rax											;save address for buffer
				
				alloc	rax, bufferSize									;create new buffer
				
	totalBytes:	sub		r13, r13											;total bytes written
	
	readBytes:	file 	[inputFD], bufferSize, sys_read						;fd|bytes|mode macro
				cmp		rax, 0												;check return from kernel
				jge		readOk												;rax < 0	
				msg		readError											;display error
				jmp		delete												;delete memory and exit function
	
	readOk:		mov 	r8, rax												;save bytes read
	
	xorBytes:	push	rsi													;buffer address
				push	r8													;buffer size
				push	userKey												;key address
				push	r9													;key length
				call	EncryptMe											;encrypt/decrypt

	writeBytes:	file 	[outputFD], r8, sys_write							;fd|bytes|mode macro
				cmp		rax, 0												;check return from kernel
				jge		writeOk												;rax < 0	
				msg		writeError											;display error
				jmp		delete												;delete memory and exit function

	writeOk:	add 	r13, rax											;accumulate bytes written	

				
	loopCheck:	cmp		rax, bufferSize										;check bytes written
				je		readBytes											;loop if equal to buffer

	close:		mov		rax, sys_close										;sys_close
				mov 	rdi, [inputFD]										;file descriptor
				syscall														;call kernel
				
				mov		rax, sys_close										;sys_close
				mov 	rdi, [outputFD]										;file descriptor
				syscall														;call kernel
			
	result:		msg		bytesWritten							;display total bytes message
				push	r13										;total bytes value address
				call	Print64bitSNumDecimal					;display total bytes
				call	Printendl								;print new line

	delete:		mov		rax, sys_brk								;sys_brk
				mov 	rdi, [originalBreak]					;restore original memory limit
				syscall											;call kernel

	exit:		msg		closeDisplay										;print message
				mov		rax, 60												;60 = system exit
				mov		rdi, 0												;0 = return code
				syscall														;Poke the kernel

			
EncryptMe:	setupFrame														;setup stack
			saveRegisters														;save registers
			sub 	rbx, rbx												;temp key storage
			sub 	rcx, rcx												;buffer index
			mov 	rsi, QWORD[rbp+QWORDSIZE*5]								;buffer address									
			mov 	r13, QWORD[rbp+QWORDSIZE*3]								;key address

			keyLimit:	sub		rax, rax									;key index
			encrypt:	cmp 	rax, QWORD[rbp+QWORDSIZE*2]					;compare key index and length
						je		keyLimit									;if index = length

						mov 	bl, [r13+rax]								;move a key to register
						xor 	BYTE[rsi+rcx], bl							;xor with byte in buffer
						inc 	rax											;increment key index
						inc 	rcx											;increment buffer index
						cmp 	rcx, QWORD[rbp+QWORDSIZE*4]					;compare buffer index and length/size
						jl 		encrypt										;if index < length
	
			restoreRegisters												;restore registers
			closeFrame														;close stack
			ret 32
