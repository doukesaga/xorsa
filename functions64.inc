;
;Include file for the functions library
;

%macro  PUSHREGS 0
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

%macro  POPREGS 0
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


;Print the data for a current function/procedure's stack frame
;Notes:
;	This function assumes you have created a valid stack frame
;	Call this function after the stack frame is created an all
;	local function variables have been allocated and before you use
;	the stack for any other purposes
;Stack contents:
;	None
;Example Usage:
;	call	PrintStackFrame
;
extern		PrintStackFrame

;Print a tab character to stdout
;Stack contents:
;	None
;Example Usage:
;	call	PrintTab
;
extern		PrintTab

;Print all Quad Word values found in an array
;Stack Contents:	
;	Address of the Array (Stack)
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintQWordArray
extern		PrintQWordArray

;Print all Quad Word values found in an array in Decimal Format
;Stack Contents:	
;	Address of the Array (Stack)
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintQWordArrayDec
extern		PrintQWordArrayDec

;Print all Quad Word signed values found in an array in Decimal Format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintSQWordArrayDec
extern		PrintSQWordArrayDec

;Print all byte values found in an array in Hex format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintByteArray
extern		PrintByteArray

;Print all byte values found in an array in Decimal format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintByteArrayDec
extern		PrintByteArrayDec

;Print all signed byte values found in an array in Decimal format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintSByteArrayDec
extern		PrintSByteArrayDec

;Print all word values found in an array in Hex format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintWordArray
extern		PrintWordArray

;Print all word values found in an array in Decimal format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintWordArrayDec
extern		PrintWordArrayDec

;Print all signed word values found in an array in Decimal format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintSWordArrayDec
extern		PrintSWordArrayDec

;Print all Double Word values found in an array in Hex format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintDWordArray
extern		PrintDWordArray

;Print all Double Word values found in an array in Decimal format
;Stack Contents:	
;	Address of the Array
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintDWordArrayDec
extern		PrintDWordArrayDec

;Print all signed Double Word values found in an array in Decimal format
;Stack Contents:	
;	Address of the Array (Stack)
;	Number of items in the array
;Example Usage:
;	push	ArrayToPrint
;	push	NumerOfEntriesInArray
;	call	PrintSDWordArrayDec
extern		PrintSDWordArrayDec

;Print a string with an ending 00h delimiter to the console
;Stack Contents:
;	Address of the String (Stack)
;Example Usage:
;	push	stringVariable
;	call	PrintString
extern		PrintString

;Get the length of a null-terminated string.  Can be used for functions
;which need a string length and don't search for null-terminated characters
;Stack Contents:
;	Address of the String (Stack)
;Return Value:
;	RAX will equal the length of the string
;Example Usage:
;	push	stringVariable
;	call	StringLength
extern		StringLength

;Print a space to the console
;Stack Contents:
;	None
;Example Usage:
;	call	PrintSpace
extern		PrintSpace

;Print 'x' number of spaces
;Stack Contents:
;	the total spaces to print
;Example Usage:
;	push	DWORD 5
;	call	PrintSpaces
extern		PrintSpaces

;Print a comma to the console
;Stack Contents:
;	None
;Example Usage:
;	call	PrintComma
extern		PrintComma

;Print a new line to the console
;Stack Contents:
;	None
;Example Usage:
;	call	Printendl
extern		Printendl

;Print a string which is not null terminated
;Stack contents:
;	The Address of the string to print
;	The length of the string to print
;Example Usage:
;	push	stringVariable
;	push	stringVariable.len
;	call	PrintText
extern		PrintText

;Convert and then print a 64bit hex number
;Stack contents:
;	Value to Convert to an Ascii String
;Example Usage:
;	push	QWORD [quadWordVariable]
;	call	Print64bitNumHex
extern		Print64bitNumHex
   
;Convert and then print a 64bit octal number
;Stack contents:
;	Value to Convert to an Ascii String
;Example Usage:
;	push	QWORD [quadWordVariable]
;	call	Print64bitNumOctal
extern		Print64bitNumOctal

;Convert and then print a 64bit decimal number
;Stack contents:
;	Value to Convert to an Ascii String
;Example Usage:
;	push QWORD [quadwordvariable]
;	call	Print64bitNumDecimal
extern		Print64bitNumDecimal

;Convert and then print a signed 64bit decimal number
;Stack contents:
;	Value to Convert to an Ascii String
;Example Usage:
;	push QWORD [quadwordvariable]
;	call	Print64bitNumDecimal
extern		Print64bitSNumDecimal

;Convert and then print a 64bit binary number
;Stack contents:
;	Value to Convert to an Ascii String
;Example Usage:
;	push QWORD [quadwordvariable]
;	call	Print64bitNumBinary
extern		Print64bitNumBinary

;Print a full 64bit binary number including leading zeros
;Stack contents:
;	Value to Convert to an Ascii String
;Example Usage:
;	push QWORD [quadwordvariable]
;	call	Print64bitFullBinary
extern		Print64bitFullBinary

;This routine prints a string to the screen left justified
;Stack contents:
;	Address of the string [ebp + 16]
;	Number of characters it will be justified within [ebp + 24]
;Example Usage:
;	push	stringVariable
;	push	QWORD 80
;	call	PrintLeft
extern		PrintLeft

;This routine prints a string to the screen right justified
;Stack contents:
;	Address of the string [ebp + 16]
;	Number of characters it will be justified within [ebp + 24]
;Example Usage:
;	push	stringVariable
;	push	QWORD 80
;	call	PrintRight
extern		PrintRight

;This routine prints a string to the screen center justified
;Stack contents:
;	Address of the string [ebp + 16]
;	Number of characters it will be justified within [ebp + 24]
;Example Usage:
;	push	stringVariable
;	push	QWORD 80
;	call	PrintCenter
extern		PrintCenter

;Print all 64bit Registers to the screen
;Stack contents:
;	None
;Example Usage:
;	call	PrintRegisters
extern		PrintRegisters

;Call the necessary interrupt with the necessary register values to read data from the keyboard
;Stack Contents:
;	Address of keyboard buffer
;	Size of the keyboard buffer
;Return:
;	Rax will contain the number of characters the user input
;Example Usage:
;	push	readbuffer
;	push	readbuffer.len
;	call	ReadText
extern		ReadText

;Input UnSigned Int 
;This function will let the user input an integer returned into the RAX register
;Arguments: None
;Return: 	rax will contain the usigned ingeter
;			Carry flag will be set if invalid integer was input
;Example Usage:
;	call	InputInt
;	Note: eax will contain the value of the unsigned integer entered
;	jnc		validIntegerInput
;	Otherwise, an invalid integer was input
extern		InputUInt

;Input Signed Int 
;This function will let the user input a signed integer and put the value 
;into the RAX register.
;Arguments: None
;Return: 	eax will contain the usigned ingeter
;			Carry flag will be set if invalid integer was input
;Example Usage:
;	call	InputSInt
;	Note: eax will contain the value of the signed integer entered
;	jnc		validIntegerInput
;	Otherwise, an invalid integer was input
extern		InputSInt

;Call the necessary interrupt with the necessary register values to read data from the keyboard
;Stack Contents:
;	Address of the string to print
;	Address of keyboard buffer
;	Size of the keyboard buffer
;Return:
;	Rax will contain the number of characters input
;Example Usage:
;	push	inputPromptVariable
;	push	keyboardBufferVariable
;	push	keyboardBufferVariable.len  ;This is the maximum size of the buffer
;	call	ReadTextWPrompt
extern		ReadTextWPrompt

;Print a Quad-word floating point number
;Stack Contents:
;	The number of fractional digits to print
;	The floating point number to print
;Return:
;	None
;Example Usage:
;	push	numberToPrint
;	push	[fractionalDigits]
;	call	PrintQWFloat
extern		PrintQWFloat

;Print a Double-word floating point number with scientific notation
;This version uses the integer extraction power of the FPU instead of moving bits
;	around to extract the exponent and left/right mantissa's making this a
;	much easier and shorter algorithm
;Stack Contents:
;	The number of fractional digits to print
;	The floating point number to print
;Return:
;	None
;Example Usage:
;	push	[numberToPrint]
;	push	[fractionalDigits]
;	call	PrintQWFloatSN
extern		PrintQWFloatSN

;Input a Floating Point Number	
;This function will let the user input a string, then it will check it to make sure it
;is a valid floating point number.  It will then convert the ASCII string into a QWORD 
;and return that value in the RAX register.
;Stack Contents:
;	None
;Return: 	RAX and ST(0) will contain the number
;			Carry flag will be set if invalid binary number was input
;Example Usage:
;	call	InputFloat
;	jnc		ValidFloatLabel
;	otherwise, a problem occured - print an error message
extern		InputFloat
	
;Input Binary Number
;This function will let the user input a string, then it will check it to make sure it
;is a binary string.  It will then convert the ASCII string into a DWORD and return
;that value in the RAX register.
;Stack Contents:
;	None
;Return: 	rax will contain the numeric binary value
;			Carry flag will be set if invalid binary number was input
;Example Usage:
;	call	InputBin
;	jnc		ValidBinLabel
;	otherwise, a problem occured - print an error message
extern		InputBin

;This function will let the user input a string, then it will check it to make sure it
;is a hexidecimal string.  It will then convert the ASCII string into a DWORD and return
;that value in the EAX register.
;Stack Contents:
;	None
;Return: 	rax will contain the numeric hexidecimal value
;			Carry flag will be set if invalid hex number was input
;Example Usage:
;	call	InputHex
;	jnc		ValidHexLabel
;	otherwise, a problem occured - print an error message
extern		InputHex

;Allocate some memory (x bytes)	and return the high address to RAX
;Stack Contents:
;	Number of BYTES to add to memory
;Return: 	RAX will contain the new high memory address
;Example Usage:
;	push	QWORD 1024			;increase memory by 1024 bytes
;	call	AllocateBytes
extern		AllocateBytes

;Free some memory (x bytes)	and return the high address to RAX
;Stack Contents:
;	Number of BYTES to remove from memory
;Return: 	RAX will contain the new high memory address
;Example Usage:
;	push	QWORD 1024			;reduce memory by 1024 bytes
;	call	FreeBytes
extern		FreeBytes

;Print all of the floating point registers ST0 - ST7
;Stack Contents:
;	None
;Return: 	None
;Example Usage:
;	call	PrintFloatingRegisters
extern		PrintFloatingRegisters

;Print a 64-bit floating point number
;Stack Contents:
;	The floating point number
;Return: 	None
;Example Usage:
;	call	Print64bitFloatBinary
extern		Print64bitFloatBinary

;Set the carry flag if the floating poing number pushed onto the Stack
;is a +NAN, -NAN, +Infinity or -Infinity
;Stack Contents:
;	QWORD Floating Point number (Stack)
;Return: Carry Flag Set if NAN, Clear if OK
;Example Usage
;   push  QWORD [floatingVariable]
;   call  IsNAN
extern		IsNAN

;Simple xor encryption/decryption of a string using a user entered key
;Stack Contents:
;	String address to encrypt/decrypt (Stack rbp + 48)
;	Length of the string to encrypt (Stack rbp + 40)
;	string address to be used as a key (Stack rbp + 32)
;	integer value indicating the length of the key (Stack rbp + 24)
;	string address where the encrypted/decrypted data should go (Stack rbp + 16)
;Return:	Total bytes encrypted in eax
;Example Usage
;   push	stringaddress
;	push	lengthofstring
;	push	keystringaddress
;	push	lengthofkey
;	push	resultaddress
;   call  EncryptString
extern		EncryptString

;Clears the keyboard buffer until \n or null are encountered
;Stack contents:
;	None
;Example Usage:
;	call	ClearKBuffer
extern		ClearKBuffer

;An Internal function used to get the system time in hours
;Stack Contents:
;	None
;Return: RAX will have the current Hour
;Example Usage
;	call	GetCurrentHour
extern		GetCurrentHour

;An Internal function used to get the system time in minutes
;Stack Contents:
;	None
;Return: RAX will have the current minute
;Example Usage
;	call	GetCurrentMinute
extern		GetCurrentMinute

;An Internal function used to get the system time in seconds
;Stack Contents:
;	None
;Return: RAX will have the current seconds
;Example Usage
;	call	GetCurrentSecond
extern		GetCurrentSecond

;An Internal function used to get the system year
;Stack Contents:
;	None
;Return: RAX will have the current year
;Example Usage
;	call	GetCurrentYear
extern		GetCurrentYear

;An Internal function used to get the system month
;Stack Contents:
;	None
;Return: RAX will have the current month
;Example Usage
;	call	GetCurrentMonth
extern		GetCurrentMonth

;An Internal function used to get the system day
;Stack Contents:
;	None
;Return: RAX will have the current day
;Example Usage
;	call	GetCurrentDay
extern		GetCurrentDay

;An Internal function used to get the system time hours, minutes, seconds
;Stack Contents:
;	None
;Return: None
;Example Usage
;   call GetSystemTime
extern		GetSystemTime

;Print the time in the format hh:mm:ss
;Stack Contents:
;	None
;Return: None
;Example Usage
;   call PrintSystemTime
extern		PrintSystemTime

;Print the date in the format mm/dd/yyyy
;Stack Contents:
;	None
;Return: None
;Example Usage
;   call PrintSystemDateEng
extern		PrintSystemDateEng

;Print the date in the format yyyy/mm/dd
;Stack Contents:
;	None
;Return: None
;Example Usage
;   call PrintSystemDateEuro
extern		PrintSystemDateEuro

;Convert and then return in a byte array a64-but number in decimal format
;Stack contents:
;	Value to Convert to an Ascii String
;	Address of byte array to contain the result
;Return Value:
;	rax = Number of characters returned
;Example Usage:
;	push 	QWORD [quadwordvariable]
;	push 	stringbuffer
;	call	ToString64bitNumDecimal
extern		ToString64bitNumDecimal

;Convert and then return in a byte array a 64bit signed number in decimal format
;Stack contents:
;	Value to Convert to an Ascii String
;	Address of byte array to contain the result
;Return Value:
;	rax = Number of characters returned
;Example Usage:
;	push 	QWORD [quadwordvariable]
;	push 	stringbuffer
;	call	ToString64bitSNumDecimal
extern		ToString64bitSNumDecimal

;Get the system date in English format and return to the calling function in th array
;	provided
;Stack contents:
;	Address of byte array to contain the result
;Return Value:
;	rax = Number of characters returned
;Example Usage:
;	push 	stringbuffer
;	call	GetEngDateString
extern		GetEngDateString

;Get the system date in European format and return to the calling function in th array
;	provided
;Stack contents:
;	Address of byte array to contain the result
;Return Value:
;	rax = Number of characters returned
;Example Usage:
;	push 	stringbuffer
;	call	GetEuroDateString
extern		GetEuroDateString

;Get the system time and return to the calling function in th array
;	provided
;Stack contents:
;	Address of byte array to contain the result
;Return Value:
;	rax = Number of characters returned
;Example Usage:
;	push 	stringbuffer
;	call	GetTimeString
extern		GetTimeString


;Get a random number from the CPU
;Stack contents:
;	The maximum value of the random number
;	Signed = 1, Unsigned = 0
;Return Value:
;	rax = Random number value
;Example Usage:
;	push 	QWORD 200			;Will create a random number no greater than 200
;	push	QWORD 1				;1 = signed, 0 = uinsigned
;	call	GetRandomInt
extern		GetRandomInt

;Calculate the Variance from an array of numbers returning an integer result
;Stack contents:
;	Address of sample array of Quad words
;	The number of samples to process
;Return Value:
;	rax = Calculated Variance
;Example Usage:
;	push 	sampleArray			;Address of the array of numeric samples
;	push	10					;process 10 of the numbers in the array
;	call	CalcVariance
extern		CalcVariance


;Calculate the Variance from an array of numbers returning a floating point number
;Stack contents:
;	Address of sample array of Quad words
;	The number of samples to process
;Return Value:
;	rax = Calculated Variance
;Example Usage:
;	push 	sampleArray			;Address of the array of numeric samples
;	push	10					;process 10 of the numbers in the array
;	call	CalcVariance
extern		CalcVarianceFloat

;Calculate the Standard Deviation from an array of numbers
;Stack contents:
;	Address of sample array of Quad words
;	The number of samples to process
;Return Value:
;	rax = Calculated Standard Deviation
;Example Usage:
;	push 	sampleArray			;Address of the array of numeric samples
;	push	10					;process 10 of the numbers in the array
;	call	CalcStdDev
extern		CalcStdDev

;Calculate the Mean from an array of numbers
;Stack contents:
;	Address of sample array of Quad words
;	The number of samples to process
;Return Value:
;	rax = Calculated Mean
;Example Usage:
;	push 	sampleArray			;Address of the array of numeric samples
;	push	10					;process 10 of the numbers in the array
;	call	CalcMean
extern		CalcMean

;Fills an array with random quad values
;Stack contents:
;	Address of array of Quad words
;	The number of samples to process
;	Maximum value of the random number(s)
;	Signed = 1, Unsigned = 0
;Return Value:
;	Nothing
;Example Usage:
;	push 	sampleArray			;Address of the array of numeric samples
;	push	10					;process 10 of the numbers in the array
;	push	500					;The maximum random value should be 500
;	push	0					;Unsigned only
;	call	RandomArray
extern		RandomArray

;Calculate the sum from an array of numbers
;Stack contents:
;	Address of sample array of Quad words
;	The number of samples to process
;Return Value:
;	rax = Calculated Sum
;Example Usage:
;	push 	sampleArray			;Address of the array of numeric samples
;	push	10					;process 10 of the numbers in the array
;	call	CalcSumArray
extern		CalcSumArray

;Calculate the GCD of two numbers passed to this function
;Stack contents:
;	Integer #1
;	Integer #2
;Return Value:
;	rax = Calculated Greatest Common Denominator
;Example Usage:
;	push 	15					;Our first number
;	push	5					;Our second number
;	call	CalcGCD
extern		CalcGCD

;Calculate the factorial of a number passed to this function
;Stack contents:
;	Integer number to factor
;Return Value:
;	rax = Calculated Factorial of the argument passed in
;Example Usage:
;	push 	15				;The number fo factor - 15 in this case
;	call	CalcFactorial
extern		CalcFactorial

;Calculate the factorial of a number passed to this function
;Stack contents:
;	Integer number to factor
;Return Value:
;	rax = Calculated Factorial of the argument passed in floating point format
;Example Usage:
;	push 	15				;The number fo factor - 15 in this case
;	call	CalcFactorialFloat
extern		CalcFactorialFloat

