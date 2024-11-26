// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "include/capstone/capstone.h"
#pragma comment(lib,"capstone.lib")

//导出函数---反汇编一条语句
extern "C"
__declspec(dllexport) size_t __stdcall dllmain( uint8_t* code/*机器码*/, 
                                                int nCodeLen, /*传入的机器码长度*/
                                                int nAddr/*反汇编地址*/, 
                                                char* szAsm,   //反汇编内容
                                                char* szCode) {//反汇编机器码
    int nRetCount;
    csh handle;
    cs_insn* insn = nullptr;
    char szTemp[16] = {};

    // 打开 Capstone 反汇编器
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
        return 0;//失败返回0



    // 反汇编机器码
    size_t count = cs_disasm(handle, code, nCodeLen, nAddr, 1, &insn);
    if (count <= 0)
    {
        return 0;
    }


    //机器码
    for (size_t j = 0; j < insn->size; j++)
    {
        sprintf(szTemp,"%02X ", insn->bytes[j]);
        strcat(szCode, szTemp);
    }
    //对齐
    for (size_t j = 0; j < 30 - insn->size * 3; j++)
    {
        strcat(szCode, " ");
    }
    //反汇编内容
    sprintf(szAsm," %s %s", insn->mnemonic, insn->op_str);

    // 释放内存
    nRetCount = insn->size;
    cs_free(insn, count);
    cs_close(&handle);
    return nRetCount;//返回条数

}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

