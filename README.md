# ToPaWaf
Pwn waf for AWD/AWDP

不使用沙箱或syscall之类的方案完成通防，目前只支持使用 read 完成输入的题型，但是绝大多数 pwn 题都通过这个方式读取，因此只支持到这一步。目前只支持 amd64 。
