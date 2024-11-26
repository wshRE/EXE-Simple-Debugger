.586
.model flat, stdcall
option casemap:none

include windows.inc
include msvcrt.inc
include kernel32.inc
include user32.inc
includelib kernel32.lib
includelib msvcrt.lib
includelib user32.lib
includelib Dll1.lib   ;反汇编

;反汇编接口
dllmain proto  code:dword, nCodeLen:dword, nAddr:dword, szAsm:dword,szCode:dword
;链表增加数据
InsertLst proto pHead:ptr PointNodeStruct, pUserData:DWORD
;链表通过序号删除数据
DeleteLstByIndex proto  pHead:ptr PointNodeStruct, nIdx:DWORD
;链表删通过节点除数据
DeleteLst proto  pHead:ptr PointNodeStruct, pNodeToDel:ptr PointNodeStruct
;显示反汇编代码
ShowAsm proto 
;获取输入的命令并分发处理
InputCommand proto 
CommandBC proto                 ;删除int3断点
CommandBP proto                 ;下int 3 断点
CommandBL proto                 ;显示所有int3断点
CommandT proto                   ;单步步入
CommandP proto                   ;单步步过
BreakPoint proto                    ;处理接收到的软件断点异常
SingleStep proto                    ;处理接收到的单步异常
CommandAutoP proto         ;trace
CommandBPH proto               ;硬件断点
SetBPH proto  dwAddr:DWORD,dwLen:DWORD,dwType:DWORD                          ;设置硬件断点
CommandBM  proto              ;硬件访问断点()

AccessViolation proto           ;C05
CommandDUMP proto         ;内存dump
PeMessInit proto                    ;PE信息获取
CommandG proto                  ;执行到xx位置
CommandU proto                  ;反汇编8条代码
CommandR proto                  ;显示寄存器
CommandDD proto             ;显示内存数据
CommandDE proto              ;修改内存数据
CommandRET proto            ;执行到返回
ConmmandDLL proto         ;显示DLL
CommandES proto              ;导出脚本
CommandLS proto              ;导入脚本
CommandBPM proto            ;内存断点
CommandBMC proto        ;按序号删除内存断点
CommandBML proto         ;内存断点列表
CommandBHL proto         ;显示硬件断点
CommandBHC proto        ;删除硬件断点
CloBPH proto Index:DWORD    ;取消硬件断点
CommandRC    proto          ;修改寄存器           
.data
    g_szProcess db "TestDebug.exe", 0                                         ;调试应用名称
    g_si STARTUPINFO <0>                                                        ;全局或静态变量 ，初始化为0
    g_pi PROCESS_INFORMATION <0>                                ;当前进程信息
    g_de DEBUG_EVENT <0>                                                     ;调试事件
    g_szDllName db MAX_PATH*2 dup (0)                           ;操作的dll名称
    g_szOutPutMessage db MAX_PATH*2 dup (0)             ;输出的调试信息
    m_hThread HANDLE 0                                                          ;当前产生调试消息的线程
    m_bIsSysBp BOOL TRUE                                                     ; 是否是系统断点标志（初始为True）
    m_bIsGoRet BOOL FALSE                                                   ;是否执行到返回
    ;-------------------命令--------------------------------------
    g_szCommand db 128 dup (0)                                            ;输入的命令
    g_dwBpAddr    dd 0                                                                ;bp addr
    g_szBpOldCode db 0                                                            ;bp addr 旧代码
    g_dwBcAddr    dd 0                                                                ;bc addr

    ;------------------反汇编结果----------------------------------
    g_szAsm             db 256 dup(0)                                           ;机器码
    g_szCode          db 256 dup(0)                                           ;反汇编代码
    
    ;-----------------断点结构体----------------------------------
    PointNodeStruct struct
            g_pPre  dd 0
            g_pNext dd 0
            g_pData dd 0   
    PointNodeStruct ends
    
    
    PointRecordStruct struct
	g_dwAddr DWORD 0                                                    ;地址
	g_btOldCode BYTE 0                                                    ;代码
    PointRecordStruct Ends
    g_PointListHead dd NULL                                                 ;断点链表头节点
    
    ;临时断点结构体(G命令使用)
    TempPointStruct struct
	g_dwAddr DWORD 0                                                    ;地址
	g_btOldCode BYTE 0                                                    ;代码
    TempPointStruct ends
    tempPoint TempPointStruct  <0,0>                                 ;临时断点
 ;---------------------------内存断点结构体--------------------------------   
  ;链表节点还是使用 PointNodeStruct
  ;断点信息表
  MemPointMessStruct struct
      g_dwMessAddr dd 0                                           ;地址
      g_dwLen   dd 0                                                     ;长度
      g_dwNewType  dd 0                                          ;设置的类型
      g_dwOleType dd 0                                             ;旧类型
  MemPointMessStruct ends
  
  ;断点分页表
   MemPointPageStruct struct
      g_dwMessAddr dd 0                                                    ;断点地址
      g_dwPageAddr dd 0                                                    ;分页地址
  MemPointPageStruct ends 

 ;分页表
  MemPageStruct struct
      g_dwPageAddr dd 0                                                    ;分页地址
      g_dwOldType  dd 0                                                     ;设置的类型
  MemPageStruct ends 


  g_MemPointMessListHead dd NULL                                         ;断点信息表头节点  
  g_MemPointPageListHead dd NULL                                         ;断点分页表头节点.
  g_MemPageListHead dd NULL                                                    ;分页表头节点.
  
 ;------------------------------------------------------------------   
    g_SingStepFlag  dd 0                                                           ;单步标志（1为进入单步状态）
    g_BreakPointTempFlag  dd 0                                            ;int3 断点临时使用标志
    g_BreakPointOldAddrRecord  dd 0                                 ;int3 旧地址,用来恢复原代码为CC
    
    ;P命令使用
    g_dwCurIP dd 0                                                                      ;当前指令的位置
    g_dwNextIP dd 0                                                                    ;下一条指令的位置
    g_dwCommandPOldCode   dd 0                                       ;下一条指令原始代码 
    g_dwCommandPOldAddr    dd 0                                       ;下一条指令地址
    
    ;AutoP
    g_dwTracePointAddr dd 0                                                   ;结束地址
    g_bIsTrace dd  FALSE                                                            ;是否正在trace
    
    ;BPH
    g_dwBhAddr     dd 0                                                              ;硬件断点
    g_blsBhStep     dd FALSE                                                     ;硬件段点标志
    
    ;BM
    
    ;BPM
    g_dwBmpAddr dd 0                                                                  ;地址
    g_dwBmpLen dd 0                                                                  ;长度
    g_dwBmpType dd 0                                                               ;类型 r/w
    g_dwoldProc      dd 0                                                              ;旧的内存属性
    g_blsBmpFlag   dd FALSE                                                            
    
    ;PE
    g_dwBaseOfImage dd 0                                                        ;内存模块基址
    g_pDosHeader IMAGE_DOS_HEADER <>                      ;DOS头
    g_pNtHeader IMAGE_NT_HEADERS32 <>                     ;NT头
    g_pFileHeader IMAGE_FILE_HEADER <>                        ;文件头
    g_pOptHeader  IMAGE_OPTIONAL_HEADER <>        ;选项头 
    g_pSecHeader  IMAGE_SECTION_HEADER <>         ;节表 
    g_pSecBase dd 0                                                                     ;节表地址
    g_pImageBase  dd 0                                                               ;基址
    g_pPeSize dd 0                                                                        ;pe头大小
    
    ;脚本
    g_szCommamdNum dd 0                                                      ;记录历史输入的命令数量
    g_szCommandHis    db 2000 dup(0)                                 ;记录输入的所有命令(每30个字节为一条命令)   
    g_bScriptIsRun   dd  FALSE                                                  ;脚本是否正在执行
    g_szCommandRead   db 2000 dup(0)                               ;导入的脚本   
    g_szCommandIsRun dd 0                                                      ;当前脚本已执行的命令数
    
    ;--------------------------------硬件断点--------
     BphStruct struct 
            g_dwAddr dd 0
            g_dwLen dd 0
            g_btType dd 0
            g_dwDRX dd 0
    BphStruct Ends   
    g_BPHLst dd NULL                                                                ;链表首节点
    g_nBphNum   dd 0                                                                  ;硬件断点数量
    
    ;硬件断点使用情况
    DrxFree struct
            DR_0  dd FALSE
            DR_1  dd FALSE
            DR_2   dd FALSE
            DR_3   dd FALSE
    DrxFree ends
    g_bphFree      DrxFree<0>        
.const 
    ;------------------格式化输入输出------------------------------------
    g_szAdressPr    db "%08X ",0                                               ;格式化输出地址
    g_szAdressPrNext    db "-------下一条：%08X  -------",0                                               ;格式化输出地址
    g_szBytePr        db "%02X ",0                                               ;格式化输出机器码
    g_szSpacePr     db " ",0                                                          ;格式化输出空格
    g_szStrPr           db  " %s %s",0dh,0ah,0                             ;格式化输出反汇编代码
    g_szCharPr db "%c",0                                                            ;格式化显示字符
    g_szFmtDllBase db "  load   base:0x%08x name:",0                                    ;加载的dll名称
    g_szFmtunDllBase db "unload   base:0x%08x name:",0dh, 0ah, 0         ;卸载的dll名称
    g_szRN  db 0dh, 0ah, 0                                                                                      ;回车换行
    g_szShowBP db "%d  : %08x ",0ah,0                                   ;显示断点
    g_szPointPr db ".",0                                                                ;显示未识别点
    g_szString db  " %s",0dh,0ah,0                                            ;显示字符串
    g_szEXCEPTION_DEBUG_EVENT       db "EXCEPTION_DEBUG_EVENT", 0dh, 0ah, 0                         ;1.被调试程序产生异常
    g_szCREATE_THREAD_DEBUG_EVENT   db "CREATE_THREAD_DEBUG_EVENT", 0dh, 0ah, 0      ;2.标记用于当被调试进程创建新线程时触发；
    g_szCREATE_PROCESS_DEBUG_EVENT  db "CREATE_PROCESS_DEBUG_EVENT", 0dh, 0ah, 0   ;3.当被调试进程创建新进程时触发；
    g_szEXIT_THREAD_DEBUG_EVENT     db "EXIT_THREAD_DEBUG_EVENT", 0dh, 0ah, 0                  ;4.被调试进程中的线程退出时触发；
    g_szEXIT_PROCESS_DEBUG_EVENT    db "EXIT_PROCESS_DEBUG_EVENT", 0dh, 0ah, 0               ;5.被调试进程自身退出时触发；
    g_szLOAD_DLL_DEBUG_EVENT        db "LOAD_DLL_DEBUG_EVENT", 0dh, 0ah, 0                            ;6.被调试进程加载动态链接库时触发；
    g_szUNLOAD_DLL_DEBUG_EVENT      db "UNLOAD_DLL_DEBUG_EVENT", 0dh, 0ah, 0                 ;7.被调试进程卸载动态链接库时触发；
    g_szOUTPUT_DEBUG_STRING_EVENT   db "OUTPUT_DEBUG_STRING_EVENT ："   , 0dh, 0ah, 0  ;8.被调试进程输出调试信息时触发。
    
    g_szComTip db     "[Command]:",0       
    g_szSysBreakPointTip  db "系统断点  ", 0      
    g_szBreakPointTip  db "用户断点  ", 0
    g_szBreakPointList db "断点列表:", 0dh, 0ah, 0 
    g_szSingleStepTip   db "单步：",0
    g_szCall db " call",0
    g_szBPHTip  db "到达硬件断点",0
    g_szBmpTip   db "到达内存断点,地址：%08x ,长度: %4X ,类型: %d"  , 0dh, 0ah, 0 
    g_szMemTipOne db  "与历史断点定义发生交叉" , 0dh, 0ah, 0 
    g_szShowFmtBMP db"内存断点设置成功! 断点地址:%08x 断点长度:%d 断点类型:%d ",0ah,0
    g_szBhl db "%d  地址:%08x ", 0dh, 0ah, 0 
    g_szBphSuc db "硬件断点设置成功,地址:%08X , 长度: %d , 类型 :%d , DX:%d", 0dh, 0ah, 0 
    ;-----------------------------------DUMP---------------------------------------
    g_szDumpFile db "PeNew.exe",0
    
    ;-----------------------------------显示寄存器-----------------------------------
    g_szPrintRegOne db "EAX = %08X  EBX = %08X  ECX = %08X  EDX = %08X  ESI = %08X  ", 0dh, 0ah, 0 
    g_szPrintRegTwo db "EDI = %08X  ESP = %08X  EBP= %08X  FS = %08X  ", 0dh, 0ah, 0 
    g_szPrintRegThr db "CS = %08X  DS = %08X  ES= %08X  SS = %08X   EIP = %08X ", 0dh, 0ah, 0 
    g_szPrintRegFou db "CF: %01X  PF: %01X  AF: %01X  ZF: %01X  SF: %01X  TF: %01X  IF: %01X  DF: %01X  OF: %01X ", 0dh, 0ah, 0 
    
    ;-----------------------------------脚本-------------------------------
     g_szStriptEmpty db "当前未输入命令", 0dh, 0ah, 0 
     g_szStriptReadEmpty db "脚本为空", 0dh, 0ah, 0 
     g_szScriptError db "打开文件错误", 0dh, 0ah, 0 
    g_szStriptName db "Stript.txt",0
    g_szSscriptIsRunTip db "---------脚本正在运行中,当前执行命令:%s ----------------", 0dh, 0ah, 0 
    ;-----------------------------------测试用临时--------------------------------------
    ;invoke crt_printf,offset g_szone
     ;g_szone   db "----------------------------------" , 0dh, 0ah, 0
     g_sztwo   db "测试设置回原样: addr:%08X , Len :%d , Type:%d", 0dh, 0ah, 0
     g_szthree   db "断点范围: %08X -- %08X ,当前:%08X" , 0dh, 0ah, 0
     g_szShowBMLst db "%d. %08x ",0ah,0
     g_1 db "--------------------------------------1---------------------------------" , 0dh, 0ah, 0
          g_2 db "--------------------------------------2---------------------------------" , 0dh, 0ah, 0
               g_3 db "-------------------------%08x-------------3----------%08X-----------------------" , 0dh, 0ah, 0
                    g_4 db "--------------------------------------4---------------------------------" , 0dh, 0ah, 0
                         g_5 db "--------------------------------------5---------------------------------" , 0dh, 0ah, 0
                              g_6 db "正在删除内存断点，地址：%08X，长度：%d ,类型：%d" , 0dh, 0ah, 0
      g_7  db "%08X--%d--%d" , 0dh, 0ah, 0
      g_8 db "----------------------%d-------------------------", 0dh, 0ah, 0
.code

;-----------------断点链表----------------------------------------
;链表增加数据
InsertLst proc uses ecx edx ebx esi edi pHead:ptr PointNodeStruct, pUserData:DWORD
        LOCAL @pNewNode:ptr PointNodeStruct ;新节点
        
        ;申请新节点   
        invoke crt_malloc, sizeof PointNodeStruct
        .if eax == NULL
            ret
        .endif 
        mov @pNewNode, eax
        
        ;赋值, 头插法
        mov esi, @pNewNode
        assume esi:ptr PointNodeStruct
        
        mov edi, pHead
        assume edi:ptr PointNodeStruct
        
        mov [esi].g_pPre, NULL
        mov [esi].g_pNext, edi
        mov eax, pUserData
        mov [esi].g_pData, eax
        
        .if edi != NULL
            mov eax, @pNewNode
            mov [edi].g_pPre, eax        
        .endif
        
        assume esi:nothing
        assume edi:nothing
        
        mov eax, @pNewNode
        ret
InsertLst endp

;链表通过序号删除数据
DeleteLstByIndex proc uses ecx edx ebx esi edi pHead:ptr PointNodeStruct, nIdx:DWORD
        LOCAL @dwIndex:DWORD
        
        
        mov @dwIndex,0
        mov esi, pHead
        assume esi:ptr PointNodeStruct
        mov ecx,0
        ;遍历
        .while ecx < nIdx
            mov esi, [esi].g_pNext    
            inc ecx    
        .endw  

        invoke DeleteLst, pHead, esi
        assume esi:nothing
        ret
DeleteLstByIndex endp

;链表删通过节点除数据
DeleteLst proc uses ecx edx ebx esi edi  pHead:ptr PointNodeStruct, pNodeToDel:ptr PointNodeStruct
    mov esi, pHead
    assume esi:ptr PointNodeStruct
    
    mov edi, pNodeToDel
    assume edi:ptr PointNodeStruct
    
    ;与头结点交换数据
    mov eax, [esi].g_pData
    mov [edi].g_pData, eax
    
    assume edi:nothing
    
    ;删除头结点
    mov edi, [esi].g_pNext
    assume edi:ptr PointNodeStruct
    
    .if edi!=0
        mov [edi].g_pPre, NULL    
    .endif
     
    assume edi: nothing
    
    invoke crt_free, esi
    
    ;返回新的头结点
    mov eax, edi
    ret
DeleteLst endp

;------------------Other--------------------------------------
;显示反汇编代码(一条)
ShowAsm proc uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT   ;上下文
    LOCAL @buf[64]:BYTE   ;机器码
    ;1.获取地址eip
    ;2.反汇编
    ;3.格式化显示
    ;4.返回
    
    ;获取eip
    mov @ctx.ContextFlags,CONTEXT_FULL
    invoke GetThreadContext,g_pi.hThread,addr @ctx
    ;读取机器码
    invoke ReadProcessMemory,g_pi.hProcess,@ctx.regEip,addr @buf,64,NULL
    
    ;保存信息
    mov eax,@ctx.regEip
    mov g_dwCurIP ,eax
    
    ;清空
    invoke RtlZeroMemory,addr g_szAsm,64
    invoke RtlZeroMemory,addr g_szCode,64
    invoke dllmain,addr @buf,64,@ctx.regEip,addr g_szAsm,addr g_szCode
    
    ;保存下一条指令地址   
    mov  ebx,g_dwNextIP
    mov g_dwCurIP,ebx
    add eax,@ctx.regEip
    mov g_dwNextIP,eax

    ;格式化显示（仅一条）
    ;打印地址 ;打印机器码;打印对齐        ;打印反汇编代码
    invoke crt_printf,addr g_szAdressPr, @ctx.regEip
    invoke crt_printf,addr g_szCode
    invoke crt_printf, addr g_szAsm
    invoke crt_printf,addr g_szRN
    invoke crt_printf,addr g_szAdressPrNext, g_dwNextIP
    invoke crt_printf,addr g_szRN
    ret
ShowAsm endp

;获取输入的命令并分发处理
InputCommand proc uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT   ;上下文
    LOCAL @len:DWORD
    ;1.输出提示
    ;2.获取输入的命令
        ;2.1 bp 地址
            ;2.1.1 设置断点 
    ;-------------------
     ;循环输入指令
     invoke ShowAsm
     .while 1            
            invoke RtlZeroMemory,addr g_szCommand,128
            ;更新当前地址
            mov @ctx.ContextFlags,CONTEXT_FULL
            invoke GetThreadContext,g_pi.hThread,addr @ctx
            mov eax,@ctx.regEip
            mov g_dwCurIP ,eax
            ;0.判断是否正在执行trace
            .if g_bIsTrace
                    mov eax,g_dwTracePointAddr
                    ;判断是否到了结束位置
                    .if g_dwCurIP == eax
                            mov g_bIsTrace, FALSE
                            invoke ShowAsm
                             ;1.输出输入命令提示
                            invoke crt_printf,addr g_szComTip
                             ;2.获取输入的命令
                            invoke crt_gets,addr g_szCommand  
                     .else 
                            mov g_szCommand[0],'t'
                     .endif
            ;1.判断是否正在执行到ret
            .elseif m_bIsGoRet
                     invoke CommandRET ;判断是否是RET
                     .if eax
                            mov m_bIsGoRet,FALSE    
                            invoke ShowAsm
                             ;1.输出输入命令提示
                            invoke crt_printf,addr g_szComTip
                             ;2.获取输入的命令
                            invoke crt_gets,addr g_szCommand    
                     .else 
                            mov g_szCommand[0],'t'
                     .endif
            ;2.判断是否正在执行脚本
            .elseif g_bScriptIsRun 
                    mov eax,g_szCommandIsRun
                    mov ebx,30
                    mul ebx
                    lea ebx,g_szCommandRead
                    add ebx,eax
                    ;判断是否有命令
                    invoke crt_strlen,ebx  
                    mov @len,eax
                    ;脚本执行结束
                    .if eax == 0
                            mov g_bScriptIsRun,FALSE    
                            invoke ShowAsm
                             ;1.输出输入命令提示
                            invoke crt_printf,addr g_szComTip
                             ;2.获取输入的命令
                            invoke crt_gets,addr g_szCommand
                    .else
                            ;将命令拷贝到g_szCommand中
                            invoke crt_strcpy,addr g_szCommand,ebx,30
                            ;显示提示
                            invoke crt_printf,addr g_szSscriptIsRunTip,addr g_szCommand
                            ;更新执行情况
                            inc g_szCommandIsRun
                    .endif
            .else
                         ;1.输出输入命令提示
                        invoke crt_printf,addr g_szComTip
                         ;2.获取输入的命令
                        invoke crt_gets,addr g_szCommand   
                        ;3.记录输入的命令(导出脚本用),脚本相关命令不记录
                        .if !((g_szCommand[0] == 'e' || g_szCommand[0] == 'E' || g_szCommand[0] == 'l' || g_szCommand[0] == 'L') && (g_szCommand[1] == 's' || g_szCommand[1] == 'S'))
                                ;1.获取存储最后的地址
                            mov eax,g_szCommamdNum
                            mov ebx,30
                            mul ebx
                            lea ebx,g_szCommandHis
                            add ebx,eax
                                ;2.存入
                            invoke crt_strcpy,ebx,addr g_szCommand,30
                            ;4.更新输入的命令数量
                            inc g_szCommamdNum
                      .endif
            .endif
            

            
            ;1.BPH---硬件断点
            .if (g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'p' || g_szCommand[1] == 'P')   && (g_szCommand[2] == 'h' || g_szCommand[2] == 'H') 
                    invoke CommandBPH
            ;2.BPM +addr+len+r/w ---内存断点
            .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'p' || g_szCommand[1] == 'P')   && (g_szCommand[2] == 'm' || g_szCommand[2] == 'M') 
                    invoke CommandBPM
             ;显示硬件断点
            .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'H' || g_szCommand[1] == 'h')   && (g_szCommand[2] == 'l' || g_szCommand[2] == 'L') 
                    invoke CommandBHL
            ;删除硬件断点
             .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'H' || g_szCommand[1] == 'h')   && (g_szCommand[2] == 'c' || g_szCommand[2] == 'C') 
                    invoke CommandBHC           
            ;按序号删除内存断点
            .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'M' || g_szCommand[1] == 'm')   && (g_szCommand[2] == 'C' || g_szCommand[2] == 'c') 
                    invoke CommandBMC
            ;内存断点列表
            .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'M' || g_szCommand[1] == 'm')   && (g_szCommand[2] == 'L' || g_szCommand[2] == 'l') 
                     invoke CommandBML
            ;2.G --继续
            .elseif(g_szCommand[0] == 'g' || g_szCommand[0] == 'G')
                    invoke CommandG
                    ret
            ;3.BC --删除Int3断点
            .elseif (g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'c' || g_szCommand[1] == 'C')        
                    invoke CommandBC
            ;4.BL -- 显示所有断点        
            .elseif (g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'l' || g_szCommand[1] == 'L')        
                    invoke CommandBL
             ;5.trace      ---自动执行P,直到指定的地址
             .elseif(g_szCommand[0] == 't' || g_szCommand[0] == 'T') && (g_szCommand[1] == 'r' || g_szCommand[1] == 'R')   && (g_szCommand[2] == 'a' || g_szCommand[2] == 'A')              
                    invoke CommandAutoP
            ;6.T -- 单步步入
            .elseif (g_szCommand[0] == 't' || g_szCommand[0] == 'T')       
                    invoke CommandT
                    ret
            ;7.P -- 单步步过
            .elseif (g_szCommand[0] == 'p' || g_szCommand[0] == 'P')       
                    invoke CommandP
                    ret
            .elseif(g_szCommand[0] == 'r' || g_szCommand[0] == 'R') && (g_szCommand[1] == 'c' || g_szCommand[1] == 'C')        
                    invoke CommandRC
            ;8.BP--打int3断点
            .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'p' || g_szCommand[1] == 'P')              
                    invoke   CommandBP    
             ;9.BM---硬件访问断点
              .elseif(g_szCommand[0] == 'b' || g_szCommand[0] == 'B') && (g_szCommand[1] == 'm' || g_szCommand[1] == 'M')     
                      invoke   CommandBM                    
             ;10.DUMP
             .elseif (g_szCommand[0] == 'd' || g_szCommand[0] == 'D') && (g_szCommand[1] == 'u' || g_szCommand[1] == 'U')          
                       invoke CommandDUMP
             ;反汇编
             .elseif(g_szCommand[0] == 'u' || g_szCommand[0] == 'U')
                        invoke CommandU
             ;执行到返回
             .elseif(g_szCommand[0] == 'r' || g_szCommand[0] == 'R')&& (g_szCommand[1] == 'e' || g_szCommand[1] == 'E')&& (g_szCommand[2] == 't' || g_szCommand[2] == 'T')
                        mov m_bIsGoRet,TRUE
                        ;invoke CommandRET
             ;寄存器
             .elseif(g_szCommand[0] == 'r' || g_szCommand[0] == 'R')
                        invoke CommandR
             ;显示内存数据
             .elseif(g_szCommand[0] == 'd' || g_szCommand[0] == 'D') && (g_szCommand[1] == 'd' || g_szCommand[1] == 'D')     
                        invoke CommandDD
             ;修改内存数据
             .elseif(g_szCommand[0] == 'd' || g_szCommand[0] == 'D') && (g_szCommand[1] == 'e' || g_szCommand[1] == 'E')
                        invoke CommandDE     ;de + addr + mess
             ;显示DLL           
              .elseif(g_szCommand[0] == 'd' || g_szCommand[0] == 'D') && (g_szCommand[1] == 'l' || g_szCommand[1] == 'L')
                        invoke ConmmandDLL
              ;导入脚本 
              .elseif(g_szCommand[0] == 'l' || g_szCommand[0] == 'L') && (g_szCommand[1] == 's' || g_szCommand[1] == 'S')                       
                        invoke CommandLS
              ;导出脚本
              .elseif(g_szCommand[0] == 'e' || g_szCommand[0] == 'E') && (g_szCommand[1] == 's' || g_szCommand[1] == 'S') 
                        invoke CommandES                 
             .endif         
    .endw    
    ret 
InputCommand endp

;接收到软件断点时的处理
BreakPoint proc uses ecx edx ebx esi edi
    LOCAL @pAddr:DWORD              ;异常记录中的异常地址
    LOCAL @ctx:CONTEXT                ;上下文
    LOCAL @old:DWORD
    
    ;保存异常地址
    mov @pAddr,0
    invoke crt_memcpy,addr @pAddr,offset g_de.u.Exception.pExceptionRecord.ExceptionAddress,sizeof @pAddr  
    
    ;情况一：int3断点（在链表中）
    mov esi, g_PointListHead
    assume esi:ptr PointNodeStruct

    ;循环遍历链表，查看是否匹配
     .while esi != NULL 
        mov eax,[esi].g_pData
        assume eax:ptr PointRecordStruct
        mov ebx,[eax].g_dwAddr
        .if ebx==@pAddr           
            ;还原代码
            invoke WriteProcessMemory,g_pi.hProcess,@pAddr,addr [eax].g_btOldCode,1  ,NULL
            ;TF置1
            mov @ctx.ContextFlags,CONTEXT_FULL
            invoke GetThreadContext,g_pi.hThread,addr @ctx
            or @ctx.regFlag,100h
            dec @ctx.regEip
            mov eax,@ctx.regEip
            invoke SetThreadContext,g_pi.hThread,addr @ctx
            ;invoke ShowAsm
            mov g_BreakPointTempFlag,1
            mov g_BreakPointOldAddrRecord,ebx
        .endif
        assume eax:nothing
        mov esi, [esi].g_pNext
    .endw    
    
    ;情况二.P命令导致的临时断点
    mov ebx,g_dwCommandPOldAddr
    .if @pAddr == ebx
            invoke crt_printf,addr g_szSingleStepTip
             ;还原代码
            invoke WriteProcessMemory,g_pi.hProcess,@pAddr,addr g_dwCommandPOldCode,1  ,NULL   
            ;eip-1
            mov @ctx.ContextFlags,CONTEXT_FULL
            invoke GetThreadContext,g_pi.hThread,addr @ctx
            dec @ctx.regEip 
            invoke SetThreadContext,g_pi.hThread,addr @ctx
    .endif
    
    
    ;情况三：Go命令导致的临时断点
    mov ebx,tempPoint.g_dwAddr
    .if ebx == @pAddr
        ;恢复代码
        invoke WriteProcessMemory,g_pi.hProcess,@pAddr,addr tempPoint.g_btOldCode,1  ,NULL   
        ;清空
        mov tempPoint.g_dwAddr,0
        mov tempPoint.g_btOldCode,0
        ;eip-1
        mov @ctx.ContextFlags,CONTEXT_FULL
        invoke GetThreadContext,g_pi.hThread,addr @ctx
        dec @ctx.regEip 
        invoke SetThreadContext,g_pi.hThread,addr @ctx
    .endif
    
    ret
BreakPoint endp


;PE信息初始化
PeMessInit proc uses ecx edx ebx esi edi
    LOCAL @dwBytesToRead
    LOCAL @dwSize
    ;获取内存模块基址
    lea edi,g_de.u
    assume edi:ptr CREATE_PROCESS_DEBUG_INFO  
    
    mov eax,[edi].lpBaseOfImage
    mov g_dwBaseOfImage,eax  
    
    ;获取DOS头
    invoke ReadProcessMemory,g_pi.hProcess,g_dwBaseOfImage ,offset g_pDosHeader, sizeof(IMAGE_DOS_HEADER), addr @dwBytesToRead
        ;获取NT头地址
    mov ebx, [g_pDosHeader].e_lfanew
    add ebx, g_dwBaseOfImage
    mov g_pImageBase,ebx
    
    ;获取NT头
     invoke ReadProcessMemory,g_pi.hProcess,ebx,offset g_pNtHeader, sizeof(IMAGE_NT_HEADERS32), addr @dwBytesToRead
    
    ;获取文件头
    add ebx,4
    invoke ReadProcessMemory,g_pi.hProcess,ebx,offset g_pFileHeader, sizeof(IMAGE_FILE_HEADER), addr @dwBytesToRead
    add ebx,sizeof(IMAGE_FILE_HEADER)  
   
    
    ;获取选项头                                 
    invoke ReadProcessMemory,g_pi.hProcess,ebx,offset g_pOptHeader, sizeof(IMAGE_OPTIONAL_HEADER), addr @dwBytesToRead    
    
    ret
PeMessInit endp

;取消硬件断点
CloBPH proc uses ecx edx ebx esi edi Index:DWORD 
    LOCAL @ctx:CONTEXT   
    
    invoke RtlZeroMemory,addr @ctx ,sizeof @ctx
    mov @ctx.ContextFlags,CONTEXT_FULL
    invoke GetThreadContext,m_hThread,addr @ctx   
    
      .if Index==0
         OR @ctx.regFlag,100h
         AND @ctx.iDr7 ,0FFFFFFFCh
         mov @ctx.iDr6,0
    .elseif Index==1
        OR @ctx.regFlag,100h
        AND @ctx.iDr7 ,0FFFFFFF3h
        mov @ctx.iDr6,0
    .elseif Index==2
        OR @ctx.regFlag,100h
        AND @ctx.iDr7 ,0FFFFFFCFh
        mov @ctx.iDr6,0   
    .elseif Index==3
        OR @ctx.regFlag,100h
        AND @ctx.iDr7 ,0FFFFFF3Fh
        mov @ctx.iDr6,0  
    .endif   
    
    ret
CloBPH endp


;处理单步异常
SingleStep proc uses ecx edx ebx esi edi
    LOCAL @btCC:byte
    LOCAL @Addr:dword  ;地址
    LOCAL @ctx:CONTEXT                ;上下文
    LOCAL @i:DWORD
    LOCAL @dwOldProc:DWORD
    LOCAL @blsTemp:DWORD
    
    ;1.单步
    ;2.int3
    ;保存异常地址
    invoke crt_memcpy,addr @Addr,offset g_de.u.Exception.pExceptionRecord.ExceptionAddress,sizeof @Addr
    ;int3 
    .if g_BreakPointTempFlag == 1
        mov  g_BreakPointTempFlag,0
        ;重设旧地址为CC
        invoke VirtualProtectEx,g_pi.hProcess,g_BreakPointOldAddrRecord,sizeof g_BreakPointOldAddrRecord,PAGE_EXECUTE,addr @dwOldProc
        mov @btCC,0CCh
        invoke WriteProcessMemory,g_pi.hProcess,g_BreakPointOldAddrRecord,addr @btCC,1,NULL
        invoke VirtualProtectEx,g_pi.hProcess,g_BreakPointOldAddrRecord,sizeof g_BreakPointOldAddrRecord,@dwOldProc,addr @dwOldProc      
    .endif
    ;重设硬件断点(遍历链表)
    mov @blsTemp,FALSE
    .if g_blsBhStep
            ;遍历链表
            mov esi,g_BPHLst 
            assume esi:ptr PointNodeStruct
            .while esi
                    mov edi, [esi].g_pData
                    assume edi:ptr BphStruct
                    ;invoke crt_printf,offset g_7,[edi].g_dwAddr,[edi].g_dwLen,[edi].g_btType
                    invoke SetBPH,[edi].g_dwAddr,[edi].g_dwLen,[edi].g_btType
                    assume edi:nothing
                    mov esi, [esi].g_pNext
            .endw
            mov g_blsBhStep,FALSE
            mov @blsTemp,TRUE
    .endif
    
    
      ;内存断点重设
     .if g_blsBmpFlag
        mov g_blsBmpFlag,FALSE
        ;重设链表中的全部断点
         mov esi, g_MemPointMessListHead
         assume esi: ptr  PointNodeStruct    
        .while esi != NULL           
               mov eax,[esi].g_pData
               assume eax:ptr MemPointMessStruct
               invoke VirtualProtectEx,g_pi.hProcess,[eax].g_dwMessAddr,[eax].g_dwLen,PAGE_NOACCESS,offset g_dwoldProc
               ;invoke VirtualProtectEx,g_pi.hProcess,g_dwBmpAddr,g_dwBmpLen,PAGE_NOACCESS,offset g_dwoldProc
               mov esi,[esi].g_pNext
        .endw            
     .endif
    
    
     ;单步
    .if g_SingStepFlag == 1        
        mov g_SingStepFlag,0
        invoke InputCommand
        ret
    .endif
    
    
    .if @blsTemp != TRUE
            ;判断是否是硬件执行断点
         mov @ctx.ContextFlags,CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS
         invoke GetThreadContext,g_pi.hThread,addr @ctx
            ;遍历
         mov esi,g_BPHLst 
         assume esi:ptr PointNodeStruct   
         mov @i,0
         .while esi
                mov edi, [esi].g_pData
                assume edi:ptr BphStruct
                mov ebx,[edi].g_dwAddr
                .if ebx == @Addr
                     mov ebx,[edi].g_btType
                     ;执行断点
                     .if ebx == 0
                                mov g_blsBhStep,TRUE
                                ;取消硬件断点
                                invoke CloBPH,@i
                                ;设置单步
                                or @ctx.regFlag,100h
                                invoke SetThreadContext,g_pi.hThread,addr @ctx
                                invoke InputCommand
                                ret               
                      .endif
                 ;访问断点
                 .elseif     
                            mov @ctx.iDr6,0
                            invoke SetThreadContext,g_pi.hThread,addr @ctx
                            invoke InputCommand
                            ret
                .endif
                inc @i 
                assume edi:nothing     
                mov esi, [esi].g_pNext
         .endw
    .endif
     
    ret
SingleStep endp


;设置硬件断点
SetBPH proc uses ecx edx ebx esi edi dwAddr:DWORD,dwLen:DWORD,dwType:DWORD
    LOCAL @ctx:CONTEXT   
    ;1.设置调试寄存器
    ;2.保存硬件断点地址
    ;3.设置DRX寄存器
    ;4.存入,更新Context
    
    
    invoke RtlZeroMemory,addr @ctx ,sizeof @ctx
    mov @ctx.ContextFlags,CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS
    invoke GetThreadContext,g_pi.hThread,addr @ctx 
    .if g_nBphNum == 0 
             mov eax,dwAddr
             mov @ctx.iDr0 ,eax
             OR @ctx.iDr7,1h
            ;设置断点长度
             shl dwLen,18            
             mov eax,dwLen 
             ;设置断点类型 
             OR @ctx.iDr7 ,eax         
             mov eax ,dwType
             shl eax,16
            OR  @ctx.iDr7 ,eax
            
            ;and @ctx.iDr7,0fff0ffffh
            ;or @ctx.iDr7,0f0000h
            ;and @ctx.iDr7,0fffdffffh
            mov g_bphFree.DR_0 ,TRUE 
            mov ebx,0
    .elseif g_nBphNum == 1 
             mov eax,dwAddr
             mov @ctx.iDr1 ,eax
             OR @ctx.iDr7 , 4h
             ;设置断点长度
             shl dwLen,22
             mov eax,dwLen
             OR @ctx.iDr7 ,eax
             ;设置断点类型
             mov eax ,dwType
             shl eax,20
             OR  @ctx.iDr7 ,eax
             mov g_bphFree.DR_1 ,TRUE
              mov ebx,1
    .elseif g_nBphNum == 2 
             mov eax,dwAddr
             mov @ctx.iDr2 ,eax
             OR @ctx.iDr7 , 10h
             ;设置断点长度
             shl dwLen,26
             mov eax,dwLen
             OR @ctx.iDr7 ,eax
             ;设置断点类型
             mov eax ,dwType
             shl eax,24
             OR  @ctx.iDr7 ,eax
            mov g_bphFree.DR_2 ,TRUE   
            mov ebx,2
    .elseif g_nBphNum == 3
             mov eax,dwAddr
             mov @ctx.iDr3 ,eax
             OR @ctx.iDr7 , 40h
             shl dwLen,30
             mov eax,dwLen
             OR @ctx.iDr7 ,eax
             mov eax ,dwType
             shl eax,28
             OR  @ctx.iDr7 ,eax
             mov g_bphFree.DR_3 ,TRUE
             mov ebx,3
    .endif
    ;存入
    invoke SetThreadContext,g_pi.hThread,addr @ctx
    mov eax,ebx
    ret
SetBPH endp


;------------------分发处理输入的命令-------------------------

CommandBP proc  uses ecx edx ebx esi edi
    LOCAL @Addr:DWORD
    LOCAL @dwOldProc:DWORD
    LOCAL @OldCode:byte
    LOCAL @btCC:DWORD
        
        
        ;地址解析
        invoke crt_strtoul ,addr g_szCommand + 3,NULL,16
        ;保存地址
        mov @Addr,eax
    .if @Addr == 0
        ret
    .endif
        ;修改目标地址内存属性为可读写
        invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,PAGE_EXECUTE,addr @dwOldProc
        ;读取一个字节并存放
        invoke ReadProcessMemory,g_pi.hProcess,@Addr,addr @OldCode,1,NULL
        ;写入CC
        mov @btCC,0CCh
        invoke WriteProcessMemory,g_pi.hProcess,@Addr,addr @btCC,1,NULL
         ;恢复保护
        invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,@dwOldProc,addr @dwOldProc      
        
        
        ;保存为新节点
        invoke crt_malloc, sizeof PointRecordStruct 
        assume eax:ptr PointRecordStruct
        mov ebx,@Addr
        mov [eax].g_dwAddr,ebx
        mov ebx,0
        mov bl,@OldCode
        mov [eax].g_btOldCode,bl
        assume eax:nothing
        
        invoke InsertLst,g_PointListHead,eax
        mov g_PointListHead, eax  

        
    ret

CommandBP endp
    
CommandBC proc  uses ecx edx ebx esi edi
        LOCAL @Index:dword                
        LOCAL @dwIndex:DWORD
        LOCAL @dwOldProc:DWORD
        LOCAL @Addr:DWORD
        LOCAL @OldCode:BYTE
        ;解析
        invoke crt_strtoul ,addr g_szCommand + 3,NULL,10
        ;保存
        mov @Index,eax
        ;恢复代码
        mov @dwIndex,0
        mov esi, g_PointListHead
        assume esi:ptr PointNodeStruct
        mov ecx,0
            ;遍历
        .while ecx < @Index
            mov esi, [esi].g_pNext    
            inc ecx    
        .endw 
        mov edi,[esi].g_pData
        assume edi:ptr PointRecordStruct
        mov eax,[edi].g_dwAddr
        mov @Addr,eax
        mov al,[edi].g_btOldCode
        mov @OldCode,al
        invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,PAGE_EXECUTE,addr @dwOldProc
        invoke WriteProcessMemory,g_pi.hProcess,@Addr,addr @OldCode,1,NULL
        invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,@dwOldProc,addr @dwOldProc      
        
        ;通过序号删除
        invoke  DeleteLstByIndex,g_PointListHead,@Index
        ;更新
        mov g_PointListHead,eax
    ret

CommandBC endp


CommandBL proc  uses ecx edx ebx esi edi
     LOCAL @index:DWORD
        
    ;提示
    invoke crt_printf, offset g_szBreakPointList
    
    mov esi, g_PointListHead
    assume esi:ptr PointNodeStruct
    
    mov @index,0
    .while esi != NULL 
        mov eax, [esi].g_pData
        assume eax:ptr PointRecordStruct
        
        invoke crt_printf,offset g_szShowBP,@index,[eax].g_dwAddr
        inc @index
        assume eax:nothing
        
        mov esi, [esi].g_pNext
    .endw
    ret

CommandBL endp

CommandT proc uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT
    ;TF置1
    mov g_SingStepFlag,1
    invoke RtlZeroMemory,addr @ctx ,sizeof @ctx
    mov @ctx.ContextFlags,CONTEXT_FULL
    invoke GetThreadContext,g_pi.hThread,addr @ctx
    or @ctx.regFlag,100h
    invoke SetThreadContext,g_pi.hThread,addr @ctx
    ret
CommandT endp


CommandP proc uses ecx edx ebx esi edi
    LOCAL @btCC:BYTE
    ;对比    
    invoke crt_strstr,offset g_szAsm,offset g_szCall
    .if !eax
        ;是call指令,下一条指令保存原先代码,设置断点(写CC)
        ;保存地址
        mov eax,g_dwNextIP
        mov g_dwCommandPOldAddr,eax
        ;读取一个字节并存放
        invoke ReadProcessMemory,g_pi.hProcess,g_dwNextIP,addr g_dwCommandPOldCode,1,NULL
        ;写入CC
        mov @btCC,0CCh
        invoke WriteProcessMemory,g_pi.hProcess,g_dwNextIP,addr @btCC,1,NULL
    .else
        ;不是call
        invoke CommandT
    .endif
    
    ret
CommandP endp


CommandAutoP proc uses ecx edx ebx esi edi
    mov g_bIsTrace,TRUE
    ;保存目标停止地址
    invoke crt_strtoul ,addr g_szCommand + 6,NULL,16
    ;保存地址
    mov g_dwTracePointAddr,eax
    ret
CommandAutoP endp




CommandDUMP proc  uses ecx edx ebx esi edi
    LOCAL @PeAddr
     LOCAL @dwBytesToRead
     ;LOCAL @SecNum      ;节表个数
     LOCAL @Temp
     LOCAL @dwSecBase
     LOCAL @TempAddr ;内存偏移 VirtualAddress
     LOCAL @TempSize  ;拷贝的字节数SizeOfRawData
     LOCAL @TempRawAddr ;文件偏移PointerToRawData
     LOCAL @hflie;文件
     LOCAL @nWite
    ;1.创建新的PE文件(pe信息在CREATE_PROCESS_DEBUG_EVENT中提前获取)
    ;2.写PE头
    ;3.写节表(选项头起始地址 + 选项头大小)
    invoke CreateFile, offset g_szDumpFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL 
    
    mov @hflie,eax   
    invoke SetFilePointer,@hflie, NULL, NULL, FILE_END
     
   ;2.写PE头
        ;获取PE头大小并创建空间
    invoke crt_malloc, [g_pOptHeader].SizeOfHeaders 
    mov g_pPeSize,eax
    invoke ReadProcessMemory,g_pi.hProcess,g_dwBaseOfImage,g_pPeSize, [g_pOptHeader].SizeOfHeaders, addr @dwBytesToRead
        ;写入PE
    invoke WriteFile,@hflie, g_pPeSize, [g_pOptHeader].SizeOfHeaders, addr @nWite , NULL
    invoke crt_free, g_pPeSize
    
    
     ;3.写节表
        ;获取节表地址
    movzx ebx,[g_pFileHeader].SizeOfOptionalHeader
    add ebx,g_pImageBase
    add ebx,24  
    mov g_pSecBase,ebx
    mov @dwSecBase,ebx
        ;获取节表数量
   movzx ecx,[g_pFileHeader].NumberOfSections     
        ;循环获取写入(从内存偏移VirtualAddress 拷贝 SizeOfRawData个字节 到 文件偏移PointerToRawData)
    mov @Temp,0
    .while @Temp < ecx
           ;读取结构体
          invoke ReadProcessMemory,g_pi.hProcess,@dwSecBase,addr g_pSecHeader, sizeof(IMAGE_SECTION_HEADER), addr @dwBytesToRead     
           ;获取VirtualAddress
          mov ebx,g_dwBaseOfImage
          mov @TempAddr,ebx
          mov eax,[g_pSecHeader].VirtualAddress
          add @TempAddr,eax        
          
          ;获取SizeOfRawData
          mov eax,[g_pSecHeader].SizeOfRawData
          mov @TempSize,eax
          
          ;获取PointerToRawData
          mov eax,[g_pSecHeader].PointerToRawData
          mov @TempRawAddr,eax
          
           ; 对齐处理
          ;mov edx, [g_pOptHeader].SectionAlignment  ;存储对齐值
          ;xor eax, eax                              ;清空eax
          ;mov ecx, @TempSize                        ;获取原始字节大小
          ;add ecx, edx                              ;将 ecx 加上 edx，这样我们可以在除法运算中将其舍入到最接近的 SectionAlignment 的倍数。
          ;sub ecx, 1                                ;舍入操作
          ;div edx                                   ;使用 div 指令执行除法运算，并将商存储在 eax 中。商即为按照 SectionAlignment 对齐后的字节数。
         ; mul edx                                   ;使用 mul 指令将获取到的对齐后的字节数乘以 edx，从而还原到真实的对齐后的大小。
          ;mov @TempSize, eax                        ;
          
          
          ;读取文件
          invoke crt_malloc, @TempSize         
          mov ebx,eax       
          invoke ReadProcessMemory,g_pi.hProcess,@TempAddr,ebx, @TempSize, addr @dwBytesToRead
          
          ;写入文件
            ;设置文件指针指向相对于文件开头@TempRawAddr个字节处
          invoke SetFilePointer,@hflie, @TempRawAddr, NULL, FILE_BEGIN
            ;写入
          invoke WriteFile,@hflie, ebx, @TempSize, addr @nWite , NULL
        
         ;跳到下一个节表
         mov eax,sizeof IMAGE_SECTION_HEADER
         add @dwSecBase,eax
         add @Temp,1
         movzx ecx,[g_pFileHeader].NumberOfSections
    .endw   
    
    invoke CloseHandle,@hflie
    ret
CommandDUMP endp


CommandG proc uses ecx edx ebx esi edi
    LOCAL @Addr:DWORD
    LOCAL @dwOldProc:DWORD
    LOCAL @OldCode:byte
    LOCAL @btCC:DWORD
    ;地址解析
    invoke crt_strtoul ,addr g_szCommand + 2,NULL,16
    ;保存地址
    mov @Addr,eax
    .if @Addr == 0
        ret
    .endif
    
    ;在指定位置设置临时断点
        ;修改目标地址内存属性为可读写
    invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,PAGE_EXECUTE,addr @dwOldProc
    ;读取一个字节并存放
    invoke ReadProcessMemory,g_pi.hProcess,@Addr,addr @OldCode,1,NULL
    ;写入CC
    mov @btCC,0CCh
    invoke WriteProcessMemory,g_pi.hProcess,@Addr,addr @btCC,1,NULL
     ;恢复保护
    invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,@dwOldProc,addr @dwOldProc      
    
    ;保存到临时断点
    mov eax,@Addr
    mov tempPoint.g_dwAddr,eax
    mov al,@OldCode
    mov tempPoint.g_btOldCode,al       
    ret
CommandG endp

CommandU proc uses ecx edx ebx esi edi
    LOCAL @Addr:DWORD         ;地址
    LOCAL @i:DWORD                  ;循环次数
    LOCAL @buf[64]:BYTE          ;机器码
    LOCAL @nAsmLen:DWORD  ;代码长度
    LOCAL @ctx:CONTEXT   ;上下文
    ;地址解析
    invoke crt_strtoul ,addr g_szCommand + 2,NULL,16
    ;保存地址
    mov @Addr,eax
    ;.if !@Addr
                ;获取eip
                mov @ctx.ContextFlags,CONTEXT_FULL
                invoke GetThreadContext,g_pi.hThread,addr @ctx
                ;读取机器码
                invoke ReadProcessMemory,g_pi.hProcess,@ctx.regEip,addr @buf,64,NULL
                    mov eax,@ctx.regEip
                mov @Addr ,eax
    ;.endif
    
    
    ;获取反汇编代码
    mov @i,0
    mov ecx,@i
    .while ecx < 8
        ;清空
        invoke RtlZeroMemory,addr g_szAsm,64
        invoke RtlZeroMemory,addr g_szCode,64
        ;读取机器码
        invoke ReadProcessMemory,g_pi.hProcess,@Addr,addr @buf,64,NULL
        .if eax == 0
            ret
        .endif
        ;获取信息
        invoke dllmain,addr @buf,64,@Addr,addr g_szAsm,addr g_szCode
        mov @nAsmLen,eax
        ;格式化显示信息
            ;打印地址 ;打印机器码;打印对齐    ;打印反汇编代码
        invoke crt_printf,addr g_szAdressPr, @Addr
        invoke crt_printf,addr g_szCode
        invoke crt_printf, addr g_szAsm
        invoke crt_printf,addr g_szRN
        ;获取下一条指令的地址
        mov eax,@nAsmLen
        add @Addr,eax

        inc @i
        mov ecx,@i
    .endw
    ret
CommandU endp

CommandR proc uses ecx edx ebx esi edi
    LOCAL @CF:DWORD
    LOCAL @PF:DWORD
    LOCAL @AF:DWORD
    LOCAL @ZF:DWORD
    LOCAL @SF:DWORD
    LOCAL @TF:DWORD
    LOCAL @IF:DWORD
    LOCAL @DF:DWORD
    LOCAL @OF:DWORD
    LOCAL @ctx:CONTEXT
    LOCAL @i:DWORD
    mov @ctx.ContextFlags,CONTEXT_FULL 
    invoke GetThreadContext,g_pi.hThread,addr @ctx
    
    mov eax,@ctx.regFlag
    AND eax,1
    mov ebx,1
    DIV ebx
    mov @CF,eax
    
    mov eax,@ctx.regFlag
    AND eax,4
    mov ebx,4
    DIV ebx
    mov @PF,eax
    
    mov eax,@ctx.regFlag
    AND eax,16
    mov ebx,16
    DIV ebx
    mov @AF,eax
    
    mov eax,@ctx.regFlag
    AND eax,64
    mov ebx,64
    DIV ebx
    mov @ZF,eax
    
    mov eax,@ctx.regFlag
    AND eax,128
    mov ebx,128
    DIV ebx
    mov @SF,eax

    mov eax,@ctx.regFlag
    AND eax,256
    mov ebx,256
    DIV ebx
    mov @TF,eax
    
    mov eax,@ctx.regFlag
    AND eax,512
    mov ebx,512
    DIV ebx
    mov @IF,eax
    
    mov eax,@ctx.regFlag
    AND eax,1024
    mov ebx,1024
    DIV ebx
    mov @DF,eax
    
    mov eax,@ctx.regFlag
    AND eax,2056
    mov ebx,2056
    DIV ebx
    mov @OF,eax
    ;显示
    invoke crt_printf,offset g_szPrintRegOne,@ctx.regEax, @ctx.regEbx, @ctx.regEcx, @ctx.regEdx, @ctx.regEsi
    invoke crt_printf,offset g_szPrintRegTwo,@ctx.regEdi,@ctx.regEsp, @ctx.regEbp,@ctx.regFs
    invoke crt_printf,offset g_szPrintRegThr,@ctx.regCs,@ctx.regDs,@ctx.regEs,@ctx.regSs,@ctx.regEip
    invoke crt_printf,offset g_szPrintRegFou,@CF,@PF,@AF,@ZF,@SF,@TF,@IF,@DF,@OF
    ret
CommandR endp

CommandDD proc uses ecx edx ebx esi edi
    LOCAL @Addr:DWORD         ;地址
    LOCAL @btCode[128]:BYTE ;显示128字节
    LOCAL @dwBytesToRead:DWORD
    LOCAL @i:DWORD
    LOCAL @j:DWORD
    ;地址解析
    invoke crt_strtoul ,addr g_szCommand + 3,NULL,16
    ;保存地址
    mov @Addr,eax
    .if @Addr == 0
        ;获取当前地址并保存
        invoke crt_memcpy,addr @Addr,offset g_de.u.Exception.pExceptionRecord.ExceptionAddress,sizeof @Addr          
    .endif
    
    ;读取内存数据
    invoke ReadProcessMemory,g_pi.hProcess,@Addr,addr @btCode,sizeof @btCode,addr @dwBytesToRead
    
    ;循环显示数据(8 * 16)
    mov @i,0
    mov ecx,@i
    .while ecx < 8
        ;显示地址
        invoke crt_printf,offset g_szAdressPr,@Addr
        ;显示内存(i*16+j)
        mov @j,0 
        mov ecx,0 
        .while ecx < 16
                ;计算下标
                mov eax,@i
                mov ebx,16
                mul ebx
                ADD eax,@j
                ;显示
                 invoke crt_printf,offset g_szBytePr,@btCode+BYTE ptr [eax]
                 ;增加计数
                 inc @j
                 mov ecx,@j 
        .endw
        
        ;显示内容
         mov @j,0  
        mov ecx,0 
        .while ecx < 16
                ;计算下标
                mov eax,@i
                mov ebx,16
                mul ebx
                ADD eax,@j
                ;获取内存字符
                mov al,@btCode+BYTE ptr [eax]
                ;转成字符
                .if al >= 32 && al <= 128
                    invoke crt_printf,offset g_szCharPr,al
                .else
                   invoke crt_printf,offset g_szPointPr
                .endif
                inc @j
                mov ecx,@j
        .endw       
         
        ;显示换行
         invoke crt_printf,  addr  g_szRN       
         
        ;行结束,更新地址        
        mov eax,@Addr
        add eax,16
        mov @Addr,eax
        inc @i
        mov ecx,@i
    .endw
    ret
CommandDD endp

CommandDE proc uses ecx edx ebx esi edi
    LOCAL @Addr:DWORD               ;写入的地址
    LOCAL @NumAddr:DWORD    ;写入的数字
    LOCAL @dwOldProc:DWORD;初始保护属性
        ;解析地址
    invoke crt_strtoul,offset g_szCommand+ 3,NULL,16
    mov @Addr,eax
    ;解析写入的数字
     invoke crt_strtoul,offset g_szCommand + 12,NULL,16
    mov @NumAddr,eax   

    ;数字转十六进制并写入s
    ;修改目标地址内存属性为可读写
    invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,PAGE_EXECUTE,addr @dwOldProc
    
    invoke WriteProcessMemory,g_pi.hProcess,@Addr,addr @NumAddr,4,NULL
     ;恢复保护
    invoke VirtualProtectEx,g_pi.hProcess,@Addr,sizeof @Addr,@dwOldProc,addr @dwOldProc     
    ret
CommandDE endp

CommandRET proc  uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT   ;上下文
    LOCAL @buf[64]:BYTE   ;机器码
    ;1.获取地址eip
    ;2.反汇编
    ;3.格式化显示
    ;4.返回
    
    ;获取eip
    mov @ctx.ContextFlags,CONTEXT_FULL
    invoke GetThreadContext,g_pi.hThread,addr @ctx
    ;读取机器码
    invoke ReadProcessMemory,g_pi.hProcess,@ctx.regEip,addr @buf,64,NULL
        
    ;清空
    invoke RtlZeroMemory,addr g_szAsm,64
    invoke RtlZeroMemory,addr g_szCode,64
    invoke dllmain,addr @buf,64,@ctx.regEip,addr g_szAsm,addr g_szCode
    
      lea eax,g_szCode  
    .if   WORD PTR [eax] == '3C'
            mov eax,TRUE
    .else
            mov eax ,FALSE
    .endif    
    ret
CommandRET endp

ConmmandDLL proc uses ecx edx ebx esi edi
        LOCAL @hSnap:HANDLE
        LOCAL @hProcessSnap:HANDLE
        LOCAL @me32:MODULEENTRY32
        LOCAL @proc32:PROCESSENTRY32
        LOCAL @procTemp:DWORD
        LOCAL @modTemp:DWORD
        ;创建模块快照
        invoke CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0  
        mov @hProcessSnap,eax

        ;获取进程
        mov @proc32.dwSize,sizeof PROCESSENTRY32
        invoke Process32First,@hProcessSnap,addr @proc32
        mov @procTemp,eax 
        .while @procTemp
                ;判断进程名是否匹配
                invoke crt_strcmp,addr @proc32.szExeFile,addr g_szProcess              
                .if eax==0  
                        ;创建模块快照
                        invoke CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,@proc32.th32ProcessID
                        mov @hSnap,eax
                       invoke RtlZeroMemory,addr @me32,sizeof MODULEENTRY32 ;申请Dll空间
                        mov @me32.dwSize,sizeof MODULEENTRY32
                        ;获取第一个模块
                        invoke Module32First,@hSnap,addr @me32
                        invoke Module32Next,@hSnap,addr @me32
                        mov @modTemp,eax
                        ;循环遍历模块
                        .while @modTemp
                            ;打印模块信息
                            invoke crt_printf,offset g_szString,addr @me32.szModule
                            ;下一个模块
                            invoke Module32Next,@hSnap,addr @me32
                            mov @modTemp,eax
                        .endw
                 .endif
                ;下一个进程
                invoke Process32Next,@hProcessSnap,addr @proc32
                mov @procTemp,eax     
        .endw
    ret
ConmmandDLL endp

CommandES proc uses ecx edx ebx esi edi
    LOCAL @bytesWritten:DWORD
    LOCAL @fileHandle:HANDLE
    mov @fileHandle,0
    .if g_szCommamdNum ==0
        invoke crt_printf,offset g_szStriptEmpty 
        ret
    .endif
    invoke CreateFile, offset g_szStriptName, 2, 0, 0, 3, 0, 0
    ;invoke  CreateFile,offset g_szStriptName,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL 
    .if eax == 0
        invoke crt_printf,offset g_szStriptEmpty 
        ret
    .endif
    mov @fileHandle,eax
    ;invoke WriteFile,@fileHandle,addr g_szCommandHis,2000,@bytesWritten,NULL   
     invoke WriteFile,@fileHandle,addr g_szCommandHis,2000,0,0  
     .if eax == 0
        invoke crt_printf,offset g_szStriptEmpty 
        ret
    .endif   
    
    
    .if @fileHandle != 0
            invoke CloseHandle,@fileHandle 
    .endif
    ret
CommandES endp

CommandLS proc uses ecx edx ebx esi edi
    LOCAL @fileHandle:HANDLE
    LOCAL @bytesWritten:DWORD
    invoke CreateFile,offset g_szStriptName,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL
    .if eax==INVALID_HANDLE_VALUE      
        invoke crt_printf,offset g_szScriptError
        ret
    .endif
    mov @fileHandle,eax
    invoke GetFileSize, eax, 0
    ;空文件
    .if eax == 0
        invoke crt_printf,addr g_szStriptReadEmpty
        invoke CloseHandle,@fileHandle
        ret
    .endif
    
    ;读取并设置标志
    mov g_bScriptIsRun,TRUE
    invoke ReadFile,@fileHandle,addr g_szCommandRead,2000,addr @bytesWritten,NULL
    
    invoke CloseHandle,@fileHandle
    ret
CommandLS endp

;硬件断点 bph addr len(1)  type     bh+Addr+1/2/4+a/e/w
CommandBPH proc uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT
    LOCAL @Addr:DWORD
    LOCAL @Len:DWORD
    LOCAL @Type:DWORD
    LOCAL @Drx:DWORD
    ;获取参数
    invoke crt_strtoul ,addr g_szCommand + 4,NULL,16
    mov @Addr,eax
    
    invoke crt_strtoul ,addr g_szCommand + 13,NULL,16
    mov @Len,eax
    
    .if g_szCommand[15] == 'a'
            mov @Type,1
    .elseif g_szCommand[15] == 'e'
            mov @Type,0
    .else ;w
            mov @Type,3
    .endif
    invoke SetBPH,@Addr,@Len,@Type
    mov @Drx,eax
    .if eax == 5
        ret
    .endif
    ;更新数量
    inc g_nBphNum
    ;插入链表
    invoke crt_malloc, sizeof BphStruct 
    assume eax:ptr BphStruct
    mov ebx,@Addr
    mov [eax].g_dwAddr,ebx
    mov ebx,@Len
    mov [eax].g_dwLen,ebx
    mov ebx,@Type
    mov [eax].g_btType,ebx
    mov ebx,@Drx
    mov [eax].g_dwDRX,ebx
    assume eax:nothing
    
    invoke InsertLst,g_BPHLst,eax
    mov g_BPHLst, eax 
    invoke crt_printf,addr g_szBphSuc,@Addr,@Len,@Type,@Drx
    ret
CommandBPH endp

CommandBHL proc uses ecx edx ebx esi edi
    LOCAL @Index:DWORD
    mov esi,g_BPHLst
    assume esi:ptr PointNodeStruct
     mov @Index,0
    .while esi != NULL 
        mov eax, [esi].g_pData
        assume eax:ptr BphStruct
        invoke crt_printf,offset g_szBhl,@Index,[eax].g_dwAddr
        inc @Index
        assume eax:nothing
        mov esi, [esi].g_pNext
    .endw
    ret
CommandBHL endp


CommandBHC proc uses ecx edx ebx esi edi
    LOCAL @Index:DWORD
    LOCAL @ctx:CONTEXT
    ;获取序号
    invoke crt_strtoul,offset g_szCommand+ 4,NULL,16
    mov @Index,eax
    
    mov @ctx.ContextFlags,CONTEXT_FULL 
    invoke GetThreadContext,g_pi.hThread,addr @ctx
    .if @Index== 0
        .if g_bphFree.DR_0 == FALSE
            ret
        .endif
        ;and @ctx.iDr7,0fffffffch
        and @ctx.iDr7,0fffffffbh
        mov g_bphFree.DR_0,FALSE
    .elseif @Index == 1
        .if g_bphFree.DR_1 == FALSE
            ret
        .endif
        and @ctx.iDr7,0fffffffeh
         mov g_bphFree.DR_1,FALSE
    .elseif @Index== 2
        .if g_bphFree.DR_2 == FALSE
            ret
        .endif
        and @ctx.iDr7,0ffffffefh
        mov g_bphFree.DR_2,FALSE
    .elseif @Index== 3
         .if g_bphFree.DR_3 == FALSE
            ret
        .endif
        and @ctx.iDr7,0ffffffbfh
        mov g_bphFree.DR_3,FALSE
    .endif
   
     mov @ctx.iDr6,0
    invoke SetThreadContext,g_pi.hThread,addr @ctx
    
    invoke DeleteLstByIndex, g_BPHLst, @Index
    mov g_BPHLst, eax   
    dec g_nBphNum
    ret
CommandBHC endp



;硬件访问断点(废弃)
CommandBM proc uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT
    LOCAL @Addr:DWORD
    LOCAL @Len:DWORD
    LOCAL @Type:DWORD
    LOCAL @Drx:DWORD
    ;获取参数
    invoke crt_strtoul ,addr g_szCommand + 4,NULL,16
    mov @Addr,eax
    
    invoke crt_strtoul ,addr g_szCommand + 13,NULL,16
    mov @Len,eax
    
    .if g_szCommand[15] == 'a'
            mov @Type,1
    .elseif g_szCommand[15] == 'e'
            mov @Type,0
    .else ;w
            mov @Type,3
    .endif
    
    ;设置调试寄存器(仅测试dr0)
    invoke RtlZeroMemory,addr @ctx ,sizeof @ctx
    mov @ctx.ContextFlags,CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS
    invoke GetThreadContext,g_pi.hThread,addr @ctx   ;在多线程环境中断不下来,只会有一个线程断下来,其他线程断不下来,因此需要遍历线程并设置,现在只能在程序入口点后才能断

    ;保存硬件断点地址
    mov eax,@Addr
    mov @ctx.iDr0,eax
    
    ;DR7的低十六位的0号位置1,设置高十六位的第0 1 号位为字节长度(设置dr0启用)
    or @ctx.iDr7,1
    ;设置r/w 和 LEN
    or @ctx.iDr7,0f0000h
    and @ctx.iDr7,0fffdffffh
    
    ;存入
    invoke SetThreadContext,g_pi.hThread,addr @ctx
    
    ret

CommandBM endp

;修改寄存器  RC eax new
CommandRC proc 
    ret
CommandRC endp

;按序号删除内存断点
CommandBMC proc uses ecx edx ebx esi edi
    LOCAL @num:DWORD
    LOCAL @dwIndex:DWORD
    LOCAL @Addr :DWORD
    LOCAL @Type :DWORD
    LOCAL @Len :DWORD
    LOCAL @dwOldProc:DWORD
    invoke crt_strtoul ,addr g_szCommand + 3,NULL,16
    mov @num,eax
    
    ;循环遍历链表 恢复属性
        mov @dwIndex,0
        mov esi, g_MemPointMessListHead
        assume esi:ptr PointNodeStruct
        mov ecx,0
        ;遍历
        .while ecx < @num
            mov esi, [esi].g_pNext    
            inc ecx    
        .endw
        assume eax:nothing
        mov eax,[esi].g_pData
        assume eax:ptr MemPointMessStruct
        mov ebx,[eax].g_dwMessAddr
        mov @Addr,ebx
        mov ebx,[eax].g_dwLen
        mov @Len,ebx
        mov ebx,[eax].g_dwOleType
        mov @Type,ebx
        invoke crt_printf,offset g_6,@Addr,@Len,@Type
        invoke VirtualProtectEx,g_pi.hProcess,@Addr,@Len,@Type,addr @dwOldProc
    
    invoke DeleteLstByIndex, g_MemPointMessListHead, @num
    mov g_MemPointMessListHead, eax
    ret
CommandBMC endp

;内存断点列表
CommandBML proc uses ecx edx ebx esi edi
     LOCAL @index:DWORD
         
    mov esi, g_MemPointMessListHead
    assume esi:ptr PointNodeStruct
    
    mov @index,0
    .while esi != NULL 
        mov eax, [esi].g_pData
        assume eax:ptr MemPointMessStruct
        
        invoke crt_printf,offset g_szShowBMLst,@index,[eax].g_dwMessAddr
        inc @index
        assume eax:nothing
        
        mov esi, [esi].g_pNext
    .endw   
    ret
CommandBML endp

;加内存断点
CommandBPM proc uses ecx edx ebx esi edi
    LOCAL @TempEndAddr:DWORD                                                                     ;输入的结束地址
    LOCAL @TempPage:DWORD                                                                            ;分页
    LOCAL @TempPageQ:MEMORY_BASIC_INFORMATION                       ;分页查询结构体--起始点
    LOCAL @TempPageQEnd:MEMORY_BASIC_INFORMATION                ;分页查询结构体--结束点
    LOCAL @TempFlag:DWORD
    LOCAL @TempOldProc:DWORD                                                                     ;旧的内存保护属性
    LOCAL @OldPageStart:DWORD
    LOCAL @OldPageEnd:DWORD
    LOCAL @NewPageStart:DWORD
    LOCAL @NewPageEnd:DWORD
    ;bmp 01005443 5000 r0/w1
    ;解析地址
    invoke crt_strtoul,offset g_szCommand+ 4,NULL,16
    mov g_dwBmpAddr,eax
    mov @TempEndAddr,eax
    ;解析长度
     invoke crt_strtoul,offset g_szCommand + 13,NULL,16
    mov g_dwBmpLen,eax   
    
    ;解析类型
    .if g_szCommand[18] == 'r'
        mov g_dwBmpType,0
     .else
          mov g_dwBmpType,1
     .endif

    
     ;保存新节点的分页
       mov ebx,g_dwBmpAddr
       and ebx,0ffff000h
       mov   @NewPageStart,ebx
       
        mov ebx,g_dwBmpAddr
        add ebx,g_dwBmpLen
       and ebx,0ffff000h
       mov   @NewPageEnd,ebx 
    
    
       ; 检测是否与已保存数据重复与交叉(不可占有同个分页)
        mov esi, g_MemPointMessListHead
        assume esi: ptr  PointNodeStruct
        .while esi != NULL
           mov eax,[esi].g_pData
           assume eax:ptr MemPointMessStruct
           
           ;两次定义的内存断点交叉
           ;.if  (g_dwBmpAddr <= ecx && g_dwBmpAddr >= ebx ) || (@TempEndAddr <= ecx  && @TempEndAddr >= ebx )
           ;        invoke crt_printf,offset g_szMemTipOne
           ;        ret
           ;.endif
           ;获取分页
           mov ebx,[eax].g_dwMessAddr
           and ebx,0ffff000h
           mov   @OldPageStart,ebx
           
            mov ebx,[eax].g_dwMessAddr
            add ebx,[eax].g_dwLen
           and ebx,0ffff000h
           mov   @OldPageEnd,ebx 
           
           mov ebx,@NewPageStart
           mov ecx,@NewPageEnd
           
           .if (ebx >= @OldPageStart && ebx <= @OldPageEnd) || (ecx >=@OldPageStart && ecx <=  @OldPageEnd)
                       invoke crt_printf,offset g_szMemTipOne
                       ret
           .endif
            mov esi, [esi].g_pNext
        .endw
        assume eax:nothing
        assume esi:nothing
    

    ;修改内存属性
    
    invoke VirtualProtectEx,g_pi.hProcess,g_dwBmpAddr,g_dwBmpLen,PAGE_NOACCESS , addr g_dwoldProc 
    
    
    ;1.插入断点信息表
    invoke crt_malloc, sizeof MemPointMessStruct 
    assume eax:ptr MemPointMessStruct
    mov ebx,g_dwBmpAddr
    mov [eax].g_dwMessAddr,ebx
    
    mov ebx,g_dwBmpLen
    mov [eax].g_dwLen,ebx
    
    mov ebx,g_dwBmpType
    mov [eax].g_dwNewType,ebx
    mov ebx,g_dwoldProc
    mov [eax].g_dwOleType,ebx
    assume eax:nothing
    ;加入链表
    invoke InsertLst,g_MemPointMessListHead,eax
    mov g_MemPointMessListHead, eax  
    
  
   
    
    ;打印提示
    invoke crt_printf,offset g_szShowFmtBMP,g_dwBmpAddr,g_dwBmpLen,g_dwBmpType
    ret

CommandBPM endp


AccessViolation proc uses ecx edx ebx esi edi
    LOCAL @ctx:CONTEXT
    LOCAL @bIsBmHit:DWORD
    LOCAL @dwOldProc:DWORD
    LOCAL @dwType:DWORD
    LOCAL @dwAddr:DWORD
    LOCAL @Type:DWORD
    LOCAL @Addr:DWORD
    LOCAL @Len:DWORD
    LOCAL @StartPage:DWORD
    LOCAL @EndPage:DWORD
    ;判断是否命中
    mov @bIsBmHit,FALSE
    
    ;获取当前位置参数
    mov eax, g_de.u.Exception.pExceptionRecord.ExceptionInformation[0]
    mov @dwType,eax
    mov eax,g_de.u.Exception.pExceptionRecord.ExceptionInformation[4]
    mov @dwAddr,eax
    
    ;循环判断是否命中或同个分页
        ;循环遍历判断是否命中
    mov esi, g_MemPointMessListHead
    assume esi: ptr  PointNodeStruct
    .while esi != NULL           
        mov eax,[esi].g_pData
        assume eax:ptr MemPointMessStruct
        ;获取遍历节点的数据
        mov ebx,[eax].g_dwOleType
        mov @dwType,ebx
        mov ebx,[eax].g_dwMessAddr
        mov @Addr,ebx
        mov ecx,[eax].g_dwLen
        mov @Len,ecx
        add ecx,ebx        
        ;命中判断
        .if @dwAddr>=ebx && @dwAddr <= ecx
                 invoke VirtualProtectEx,g_pi.hProcess,@Addr,@Len,@dwType,addr @dwOldProc
                 ;TF置1
                 mov @ctx.ContextFlags,CONTEXT_FULL
                 invoke GetThreadContext,g_pi.hThread,addr @ctx
                 or @ctx.regFlag,100h
                 invoke SetThreadContext,g_pi.hThread,addr @ctx
                 mov g_blsBmpFlag,TRUE
                invoke InputCommand
                assume eax:nothing     
                ret            
        .endif
        ;获取分页数据
        mov ebx,@Addr
        and ebx,0ffff000h
        mov   @StartPage,ebx
       
        mov ebx,@Addr
        add ebx,@Len
        and ebx,0ffff000h
        mov   @EndPage,ebx    
                       
        mov ebx,@dwAddr
        and ebx,0ffff000h                
        ;分页判断
        .if ebx >= @StartPage && ebx <= @EndPage
                 invoke VirtualProtectEx,g_pi.hProcess,@Addr,@Len,@dwType,addr @dwOldProc
                 ;TF置1
                 mov @ctx.ContextFlags,CONTEXT_FULL
                 invoke GetThreadContext,g_pi.hThread,addr @ctx
                 or @ctx.regFlag,100h
                 invoke SetThreadContext,g_pi.hThread,addr @ctx
                 mov g_blsBmpFlag,TRUE
        .endif
        assume eax:nothing     
        mov esi, [esi].g_pNext
    .endw
    assume eax:nothing     
    assume esi:nothing  
    ret
AccessViolation endp


;--------------------处理调试信息-----------------------------
;1.处理异常调试信息（输入命令，断点）
OnExceptionDebugEvent proc uses ecx edx ebx esi edi
    ;1.判断是否是系统断点
            ;1.1 反汇编代码并显示
            ;1.2 获取输入的命令
            ;1.3 返回
    ;2.判断是否是软件断点
    ;3.判断是否是单步
    ;--------------------------
    ;系统断点
    .if m_bIsSysBp
        invoke crt_printf,addr g_szSysBreakPointTip
        ;invoke ShowAsm
        invoke InputCommand  
        mov m_bIsSysBp,FALSE  
        ret
    .endif
    ;软件断点
    .if g_de.u.Exception.pExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
        ;invoke crt_printf,addr g_szBreakPointTip
        invoke  BreakPoint 
        invoke InputCommand 
        ret
     ;单步 c04
    .elseif g_de.u.Exception.pExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
        invoke SingleStep
           ret     
    ;C05
    .elseif g_de.u.Exception.pExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION
        invoke AccessViolation
        ret
    .endif
    
    ret
OnExceptionDebugEvent endp

main proc
    ;1.建立调试会话
    invoke CreateProcess, NULL, offset g_szProcess, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, offset g_si, offset g_pi 
        

    .while TRUE
        ;2.接受调试事件
        invoke WaitForDebugEvent, offset g_de, INFINITE
        .continue .if !eax  ;如果eax不为0继续

        ;保存产生消息的线程句柄
        invoke OpenThread,THREAD_ALL_ACCESS,FALSE,g_de.dwThreadId
        mov m_hThread,eax

        ;3.处理调试事件-----仅异常
        .if g_de.dwDebugEventCode ==     EXCEPTION_DEBUG_EVENT
            invoke OnExceptionDebugEvent
        .elseif g_de.dwDebugEventCode ==  CREATE_PROCESS_DEBUG_EVENT
            invoke PeMessInit
        .endif
        
        ;4.提交处理结果
        invoke ContinueDebugEvent, g_de.dwProcessId, g_de.dwThreadId, DBG_CONTINUE
        .if m_hThread
            invoke CloseHandle, m_hThread
        .endif
    .endw
    ret
main endp

ENTRY:
    invoke main
    invoke ExitProcess, 0
end ENTRY