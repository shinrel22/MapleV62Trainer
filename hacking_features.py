from XoanDbg.my_debugger import Debugger


class HackFeatures():
    def __init__(self):
        self.dbg = Debugger()
        self.procName = None
        self.pid = None
        self.h_process = None
        self.as_alloc_addr = None
        self.test = {
            "fusionVac"  : None,
            "wallXY"     : None
        }

        self.vac_alloc_addr = None
        self.ccVac_allocAddr = {
            "begin"     : None,
            "olddata"   : None,
            "pointer"   : None,
            "bool"      : None
        }

        self.fullMapAttack_allocAddr = None

        # Original Damage
        self.originalDmg = {
            0x008ECB38: "00 00 00 00 00 00 24 40",
            0x008ED758: "00 00 00 00 00 00 10 40",
            0x008ECB30: "00 00 00 00 00 00 14 40",
            0x008ED778: "33 33 33 33 33 33 0b 40"
        }


    def fullGodmode(self, active=None):
        data = {
            "addr"      : 0x007AD377,
            "data_hack" : "0F 84",
            "data"      : "0F 85"
        }
        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def missGodMode(self, active=None):
        data = {
            "missAddr": 0x007AD487,
            "data": "89 06 83 c6 04 ff 4d c0",
            "data_hack": "c7 06 00 00 00 00 90 90"
        }

        if active:
            self.dbg.write_process_memory(data["missAddr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["missAddr"], data["data"], h_process=self.h_process)


    def accHack(self, active=None):
        """
        alloc(fix,8)

        fix:
        db 66 66 66 66 66 66 E6 3F

        00424D22: //DC 0D C8 F1 8E 00 DD 5D 34 74 58 FF B6 84 00 00
        fmul qword ptr [fix]

        008ED6F8: //66 66 66 66 66 66 E6 3F 33 33 33 33 33 33 D3 3F
        db 00 00 00 E0 CF 12 63 41

        005DE247: //0F 85 9A 00 00 00 8B 7D 08 6B F6 1C 8B 03 6B FF
        db 90 90 90 90 90 90
        """

        data1 = {
            "accAddr": 0x00424D22,
            "data": "DC 0D C8 89 8E 00",
            "data_hack": "DC 0D 00 00 BD 0F"
        }

        data2 = {
            "accAddr": 0x008ED6F8,
            "data": "66 66 66 66 66 66 E6 3F",
            "data_hack": "00 00 00 E0 CF 12 63 41"
        }

        data3 = {
            "accAddr": 0x005DE247,
            "data": "0F 85 9A 00 00 00",
            "data_hack": "90 90 90 90 90 90"
        }
        if self.h_process:
            if active:
                self.dbg.write_process_memory(data1["accAddr"], data1["data_hack"], h_process=self.h_process)
                self.dbg.write_process_memory(data2["accAddr"], data2["data_hack"], h_process=self.h_process)
                self.dbg.write_process_memory(data3["accAddr"], data3["data_hack"], h_process=self.h_process)
            else:
                self.dbg.write_process_memory(data1["accAddr"], data1["data"], h_process=self.h_process)
                self.dbg.write_process_memory(data2["accAddr"], data2["data"], h_process=self.h_process)
                self.dbg.write_process_memory(data3["accAddr"], data3["data"], h_process=self.h_process)
        else:
            print("h_process is None!")

    def defHack(self, active=None):
        data = {
            "addr": 0x00670090,
            "data": "72 04",
            "data_hack": "77 04"
        }

        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def noKnockBack(self, active=None):
        data = {
            "addr": 0x007ADB78,
            "data": "7C 03",
            "data_hack": "7D 03"
        }

        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def unlimitedAtt(self, active=None):
        data1 = {
            "addr": 0x007937C5,
            "data": "39 9F",
            "data_hack": "89 9F"
        }

        data2 = {
            "addr": 0x007A7A47,
            "data": "89 08",
            "data_hack": "29 08"
        }

        if active:
            self.dbg.write_process_memory(data1["addr"], data1["data_hack"], h_process=self.h_process)
            self.dbg.write_process_memory(data2["addr"], data2["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data1["addr"], data1["data"], h_process=self.h_process)
            self.dbg.write_process_memory(data2["addr"], data2["data"], h_process=self.h_process)



    def speedAtt(self, active=None):
        """
        alloc(Hack,32)
        label(return)

        Hack:
        mov eax, -10000
        cmp eax, 02
        jg 00442de4
        jmp return

        00442DDF:
        jmp Hack
        db 90 90 90
        return:
        """
        if active:
            if self.as_alloc_addr:
                addr_alloc = self.as_alloc_addr
            else:
                addr_alloc = self.dbg.allocate(size=32, h_process=self.h_process)
                self.as_alloc_addr = addr_alloc
            if not addr_alloc:
                return False

            code1 = 0x100442DE4 - (addr_alloc + 0xE)
            code1 = self.dbg.reverseCode(hex(code1)[2:])

            code2 = (0x100442DE4 + 0x3) - (addr_alloc + 0x13)
            code2 = self.dbg.reverseCode(hex(code2)[2:])

            code3 = addr_alloc - 0x00442DE4
            code3 = self.dbg.reverseCode(hex(code3)[2:])


            sub_assembly_function = [
                ["baseAddr"            , addr_alloc],
                ["mov eax,FFFF0000"     , "B8 00 00 FF FF"],
                ["cmp eax,02"           , "83 F8 02"],
                ["jg NamLun.exe+42DE4"  , "0F 8F"+code1],
                ["jmp NamLun.exe+42DE7" , "E9"+code2]
            ]

            main_assembly_func_hack = [
                ["baseAddr"                     , 0x00442DDF],
                ["jmp <sub_assembly_function>"  , "E9"+code3]
            ]

            sub_data_hack = ""
            main_data_hack = ""

            for data1 in sub_assembly_function[1:]:
                sub_data_hack += data1[1]
            for data2 in main_assembly_func_hack[1:]:
                main_data_hack += data2[1]

            self.dbg.write_process_memory(sub_assembly_function[0][1], sub_data_hack, h_process=self.h_process)
            self.dbg.write_process_memory(main_assembly_func_hack[0][1], main_data_hack, h_process=self.h_process)

        else:
            main_assembly_func = [
                ["baseAddr", 0x00442DDF],
                ["jg NamLun.exe+42DE4", "7f 03 6a 02 58"],
            ]

            self.dbg.write_process_memory(main_assembly_func[0][1], main_assembly_func[1][1], h_process=self.h_process)


    def movSpeed(self, active=None):
        data = {
            "addr": 0x007F246D,
            "data": "0F 84 82 00 00 00",
            "data_hack": "90 90 90 90 90 90"
        }

        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def airSwim(self, active=None):
        data = {
            "addr": 0x00614CC7,
            "data": "75 04",
            "data_hack": "74 04"
        }

        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def tubi(self, active=None):
        data = {
            "addr": 0x004BECC6,
            "data": "75 36",
            "data_hack": "90 90"
        }

        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def manaRegen(self, active=None):
        data = {
            "addr": 0x00830420,
            "data": "81 FB 10 27",
            "data_hack": "81 FB 01 00"
        }

        if active:
            self.dbg.write_process_memory(data["addr"], data["data_hack"], h_process=self.h_process)
        else:
            self.dbg.write_process_memory(data["addr"], data["data"], h_process=self.h_process)


    def hpHack(self, active=None):
        # Not yet
        pass


    def fullMapAttack(self, active=None):
        """
        [ENABLE]
        alloc(FMA,64)

        FMA:
        mov edx,[00978358]
        lea edx,[edx+D5C]
        lea eax,[edx]
        jmp 005C97AD

        005C979E:
        jmp FMA
        nop
        nop
        nop
        nop

        [DISABLE]
        dealloc(FMA)

        005C979E:
        mov ecx,[ebx+00000480]
        lea eax,[ebx+00000480]
        mov eax,[eax+04]
        """
        if self.h_process:
            if active:
                if self.fullMapAttack_allocAddr:
                    fullMapAtt = self.fullMapAttack_allocAddr

                else:
                    fullMapAtt = self.dbg.allocate(h_process=self.h_process, size=64)
                    self.fullMapAttack_allocAddr = fullMapAtt

                fullMapAttData = {
                    "addr": fullMapAtt,
                    "FMA": "8B 15 58 83 97 00" + "8D 92 5C 0D 00 00" + "8D 02"
                            + "E9" + self.dbg.reverseCode(hex(0x1005C97AD - (fullMapAtt+0x13))[2:])
                }

                mainDataHack = {
                    0x005C979E: "E9" + self.dbg.reverseCode(hex(fullMapAtt - 0x005C97A3)[2:])
                }

                self.dbg.write_process_memory(fullMapAttData["addr"],
                                              fullMapAttData["FMA"],
                                              h_process=self.h_process)
                for addr in mainDataHack:
                    self.dbg.write_process_memory(addr, mainDataHack[addr], h_process=self.h_process)

            else:
                mainData = {
                    0x005C979E: "8B 8B 80 04 00 00" + "8D 83 80 04 00 00" + "8B 40 04"
                }
                for addr in mainData:
                    self.dbg.write_process_memory(addr, mainData[addr], h_process=self.h_process)
                if self.fullMapAttack_allocAddr:
                    self.dbg.freeMem(address=self.fullMapAttack_allocAddr, h_process=self.h_process)
                    self.fullMapAttack_allocAddr = None
        else:
            print("h_process is",self.h_process)


    def ccVac(self, active=None):
        """
        [ENABLE]
        alloc(begin,2048)
        alloc(olddata,32)
        alloc(pointer,4)
        alloc(bool,4)
        registersymbol(bool)
        registersymbol(olddata)
        label(set)
        label(ret)
        label(end)

        begin:
        cmp [bool],1
        je set
        ret:
        mov esi,olddata
        movsd
        movsd
        movsd
        movsd
        pop edi
        jmp end

        set:
        mov esi,[00978358]
        mov esi,[esi+24]//left wall
        mov [pointer], esi
        mov esi,[pointer]
        mov [olddata],esi
        mov esi,[00978358]
        mov esi,[esi+28]//top wall
        mov [pointer], esi
        mov esi,[pointer]
        mov [olddata+04],esi
        mov esi,[00978358]
        mov esi,[esi+2C]//right wall
        mov [pointer], esi
        mov esi,[pointer]
        mov [olddata+08],esi
        mov esi,[00978358]
        mov esi,[esi+30]//bottom wall
        mov [pointer], esi
        mov esi,[pointer]
        mov [olddata+2c],esi
        mov [bool],0
        jmp ret

        007F1156:
        jmp begin
        end:

        olddata:
        DB 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        pointer:
        DB 00 00 00 00
        bool:
        DB 01 00 00 00

        [DISABLE]
        dealloc(begin)
        dealloc(olddata)
        dealloc(pointer)
        dealloc(bool)

        007F1156:
        DB A5 A5 A5 A5 5F
        """
        if active:
            if self.ccVac_allocAddr["begin"]:
                begin = self.ccVac_allocAddr["begin"]
                olddata = self.ccVac_allocAddr["olddata"]
                pointer = self.ccVac_allocAddr["pointer"]
                booL = self.ccVac_allocAddr["bool"]
            else:
                begin = self.dbg.allocate(h_process=self.h_process, size=2048)
                olddata = self.dbg.allocate(h_process=self.h_process, size=32)
                pointer = self.dbg.allocate(h_process=self.h_process, size=4)
                booL = self.dbg.allocate(h_process=self.h_process, size=4)
                self.ccVac_allocAddr["begin"] = begin
                self.ccVac_allocAddr["olddata"] = olddata
                self.ccVac_allocAddr["pointer"] = pointer
                self.ccVac_allocAddr["bool"] = booL

            beginData = {
                "addr": begin,
                "begin": "83 3D" + self.dbg.reverseCode(hex(booL)[2:]) + "01"
                        + "0F 84 0F 00 00 00" + "BE" + self.dbg.reverseCode(hex(olddata)[2:])
                        + "A5"*4 + "5F" + "E9" + self.dbg.reverseCode(hex(0x1007F115B-(begin+0x1C))[2:])[:11],

                "set": "8B 35 58 83 97 00" + "8B 76 24" + "89 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "8B 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "89 35" + self.dbg.reverseCode(hex(olddata)[2:])
                        + "8B 35 58 83 97 00" + "8B 76 28"
                        + "89 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "8B 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "89 35" + self.dbg.reverseCode(hex(olddata+0x4)[2:])
                        + "8B 35 58 83 97 00" + "8B 76 2C"
                        + "89 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "8B 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "89 35" + self.dbg.reverseCode(hex(olddata + 0x8)[2:])
                        + "8B 35 58 83 97 00" + "8B 76 30"
                        + "89 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "8B 35" + self.dbg.reverseCode(hex(pointer)[2:])
                        + "89 35" + self.dbg.reverseCode(hex(olddata + 0x2c)[2:])
                        + "C7 05" + self.dbg.reverseCode(hex(booL)[2:]) + "00"*4
                        + "E9 76 FF FF FF"
            }

            boolData = {
                "addr": booL,
                "bool": "01"
            }

            mainDataHack = {
                0x007F1156: "E9" + self.dbg.reverseCode(hex((begin+0x100000000) - 0x007F115B)[2:])[:11]
            }
            print(hex(begin), hex(olddata), hex(pointer), hex(booL))
            print(self.dbg.reverseCode(hex(0x1007F115B - (begin + 0x1C))[2:])[:11], self.dbg.reverseCode(hex((begin+0x100000000) - 0x007F115B)[2:])[:11])
            self.dbg.write_process_memory(boolData["addr"], boolData["bool"], h_process=self.h_process)
            self.dbg.write_process_memory(beginData["addr"], beginData["begin"]
                                                            + beginData["set"],
                                                            h_process=self.h_process)
            for addr in mainDataHack:
                self.dbg.write_process_memory(addr, mainDataHack[addr], h_process=self.h_process)

        else:
            mainData = {
                0x007F1156: "A5"*4 + "5F"
            }
            for addr in mainData:
                self.dbg.write_process_memory(addr, mainData[addr], h_process=self.h_process)
            if self.ccVac_allocAddr["begin"]:
                for item in self.ccVac_allocAddr:
                    self.dbg.freeMem(h_process=self.h_process, address=self.ccVac_allocAddr[item])
                    self.ccVac_allocAddr[item] = None



    def mobsVAC(self, active=None):
        """
        [enable]
        alloc(newmem,64)
        label(retnewmem)
        label(end)

        newmem:
        cmp edi,0
        je end
        cmp [ebx+00000178],esi
        je 007f187d

        end:
        call 007f1fec
        jmp retnewmem

        007f1867:
        jmp newmem
        nop
        nop
        retnewmem:

        [disable]
        007f1867:
        je 007f186e
        call 007f1fec

        dealloc(newmem)
        """
        if self.h_process:
            if active == "left" or active == "right":
                if self.vac_alloc_addr:
                    vac = self.vac_alloc_addr
                else:
                    vac = self.dbg.allocate(h_process=self.h_process, size=64)
                    self.vac_alloc_addr = vac

                vacData = {
                    "addr": vac,
                    "vac": "83 FF 00" + "0F 84 0C 00 00 00" + "39 B3 78 01 00 00"
                            + "0F 84" + self.dbg.reverseCode(hex(0x1007F187D - (vac + 0x15))[2:]),
                    "end": "E8" + self.dbg.reverseCode(hex(0x1007F1FEC - (vac + 0x1A))[2:])
                            + "E9" + self.dbg.reverseCode(hex(0x1007F186E - (vac + 0x1F))[2:])
                }
                self.dbg.write_process_memory(vacData["addr"], vacData["vac"]
                                                                +vacData["end"],
                                                                h_process=self.h_process)

                mainDataHack = {
                    0x007f1867: "E9" + self.dbg.reverseCode(hex(vac - 0x007F186C)[2:])
                                + "90"*2
                }
                for addr in mainDataHack:
                    self.dbg.write_process_memory(addr, mainDataHack[addr], h_process=self.h_process)

                left = {
                    "addr": 0x007F4055,
                    "dataHack" : "74 53",
                    "data": "73 53"
                }
                right = {
                    "addr": 0x007F40C4,
                    "dataHack": "77 72",
                    "data": "76 72"
                }

                if "left" in active:

                    self.dbg.write_process_memory(left["addr"], left["dataHack"], h_process=self.h_process)
                    self.dbg.write_process_memory(right["addr"], right["data"], h_process=self.h_process)
                else:
                    self.dbg.write_process_memory(right["addr"], right["dataHack"], h_process=self.h_process)
                    self.dbg.write_process_memory(left["addr"], left["data"], h_process=self.h_process)

            else:
                mainData = {
                    0x007f1867: "74 05" + "E8 7E 07 00 00",
                    0x007F4055: "73 53",  # left
                    0x007F40C4: "76 72"   # right
                }
                for addr in mainData:
                    self.dbg.write_process_memory(addr, mainData[addr], h_process=self.h_process)
                if self.vac_alloc_addr:
                    self.dbg.freeMem(address=self.vac_alloc_addr, h_process=self.h_process)
                    self.vac_alloc_addr = None

        else:
            print("h_process is", self.h_process)


    def test(self, active=None):
        """[Enable]
        alloc(FusionVac,1024)
        alloc(WallXY,16)
        alloc(FVSwitch,4)
        registersymbol(FVSwitch) // change to r3gistersymbol(FVSwitch)
        label(NoVac)
        label(CharVac)
        label(CharXY)
        label(MouseVac)
        label(MouseXY)
        label(FinalizeWV)
        label(EndFusionVac)
        label(LeftWall)
        label(RightWall)
        label(TopWall)
        label(BottomWall)
        label(LeftOFF)
        label(RightOFF)
        label(TopOFF)
        label(BottomOFF)
        label(EndLeft)
        label(EndRight)
        label(EndTop)
        label(EndBottom)
        label(Fly)
        label(NoFly)
        label(EndFly)
        label(MonsterControl)
        label(EndControl)
        label(MonsterControl2)
        label(NoControl2)
        label(EndControl2)

        WallXY:
        dd 00 00 00 00
        FVSwitch:
        dd 00

        FusionVac:
        pushad
        xor eax,eax
        cmp [FVSwitch],eax
        je NoVac
        jg CharVac
        jl MouseVac

        NoVac:
        cmp eax,[WallXY]
        je FinalizeWV
        mov ebx,WallXY
        mov [ebx],eax
        mov [ebx+04],eax
        mov [ebx+08],eax
        mov [ebx+0C],eax
        jmp FinalizeWV

        CharVac:
        cmp eax,[WallXY]
        je CharXY
        inc eax
        cmp eax,[FVSwitch]
        jne CharXY
        jmp FinalizeWV
        CharXY:
        mov eax,[00979268]
        mov ebx,[eax+59C]
        mov ecx,[eax+5A0]
        mov eax,WallXY
        mov [eax],ebx
        mov [eax+04],ecx
        mov [eax+08],ebx
        mov [eax+0C],ecx
        jmp FinalizeWV

        MouseVac:
        cmp eax,[WallXY]
        je MouseXY
        dec eax
        cmp eax,[FVSwitch]
        jne MouseXY
        jmp FinalizeWV
        MouseXY:
        mov eax,[009784C0]
        mov eax,[eax+978]
        mov ebx,[eax+84]
        mov ecx,[eax+88]
        mov eax,WallXY
        mov [eax],ebx
        mov [eax+04],ecx
        mov [eax+08],ebx
        mov [eax+0C],ecx
        jmp FinalizeWV

        FinalizeWV:
        popad
        push [ebx+00000ce4]
        push [ebx+00000ce0]
        jmp EndFusionVac

        LeftWall:
        cmp [FVSwitch],00
        je LeftOFF
        fild dword ptr [WallXY]
        pop ecx
        pop ecx
        jmp EndLeft
        LeftOFF:
        fild dword ptr [ebx+24]
        pop ecx
        pop ecx
        jmp EndLeft

        RightWall:
        cmp [FVSwitch],00
        je RightOFF
        push eax
        mov eax,WallXY
        lea eax,[eax+8]
        fild dword ptr [eax]
        pop eax
        pop ecx
        pop ecx
        jmp EndRight
        RightOFF:
        fild dword ptr [ebp+08]
        pop ecx
        pop ecx
        jmp EndRight

        TopWall:
        cmp [FVSwitch],00
        je TopOFF
        push eax
        mov eax,WallXY
        lea eax,[eax+4]
        fild dword ptr [eax]
        pop eax
        pop ecx
        pop ecx
        jmp EndTop
        TopOFF:
        fild dword ptr [ebx+28]
        pop ecx
        pop ecx
        jmp EndTop

        BottomWall:
        cmp [FVSwitch],00
        je BottomOFF
        push eax
        mov eax,WallXY
        lea eax,[eax+C]
        fild dword ptr [eax]
        pop eax
        pop ecx
        pop ecx
        jmp EndBottom
        BottomOFF:
        fild dword ptr [ebp+08]
        pop ecx
        pop ecx
        jmp EndBottom

        Fly:
        cmp [FVSwitch],00
        je NoFly
        push eax
        mov eax,[00978358]
        mov eax,[eax+d74]
        sub eax,C
        cmp eax,esi
        pop eax
        je NoFly
        cmp eax,edi
        pop ecx
        pop ecx
        jne 007f1ce0
        jmp EndFly

        NoFly:
        cmp eax,edi
        pop ecx
        pop ecx
        je 007f1ce0
        jmp EndFly

        MonsterControl:
        cmp [FVSwitch],00
        je 007f946b
        jmp EndControl

        MonsterControl2:
        cmp [FVSwitch],00
        je NoControl2
        push eax
        mov eax,[00978358]
        mov eax,[eax+d74]
        sub eax,C
        cmp eax,ebx
        pop eax
        je NoControl2
        cmp [ebx+0000015c],esi
        push edi
        jne 007f186e
        jmp EndControl2

        NoControl2:
        cmp [ebx+0000015c],esi
        push edi
        je 007f186e
        jmp EndControl2

        0043F48B:
        jmp FusionVac
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        EndFusionVac:

        007F931D:
        jmp LeftWall
        EndLeft:

        007F9342:
        jmp RightWall
        EndRight:

        007F9377:
        jmp TopWall
        EndTop:

        007F939F:
        jmp BottomWall
        EndBottom:

        007F1C06:
        jmp Fly
        db 90 90 90 90 90
        EndFly:

        007F92FC:
        jmp MonsterControl
        db 90 90 90 90 90 90 90 90
        EndControl:

        007F185A:
        jmp MonsterControl2
        db 90 90 90 90
        mov [ebx+00000170],eax
        EndControl2:

        [Disable]
        dealloc(FusionVac)
        dealloc(WallXY)
        dealloc(FVSwitch)
        unregistersymbol(FVSwitch) // unr3gistersymbol(FvSwitch)

        0043F48B:
        push [ebx+00000CE4]
        push [ebx+00000CE0]

        007F931D:
        fild dword ptr [ebx+24]
        pop ecx
        pop ecx

        007F9342:
        fild dword ptr [ebp+08]
        pop ecx
        pop ecx

        007F9377:
        fild dword ptr [ebx+28]
        pop ecx
        pop ecx

        007F939F:
        fild dword ptr [ebp+08]
        pop ecx
        pop ecx

        007F1C06:
        cmp eax,edi
        pop ecx
        pop ecx
        je 007f1ce0

        007F92FC:
        cmp dword ptr [edi+00000238],03
        jne 007f946b

        007F185A:
        cmp [ebx+0000015c],esi
        push edi
        mov [ebx+00000170],eax
        je 007f186e """

        if active:
            if self.test["fusionVac"] and self.test["wallXY"]:
                fusionVac = self.test["fusionVac"]
                wallXY = self.test["wallXY"]
            else:
                fusionVac = self.dbg.allocate(h_process=self.h_process, size=1024)
                wallXY = self.dbg.allocate(h_process=self.h_process, size=16)
                self.test["fusionVac"] = fusionVac
                self.test["wallXY"] = wallXY

            print(hex(fusionVac), hex(wallXY))
            wallXYData = {
                "addr": wallXY,
                "data": "00 00 00 00"
            }

            fusionVacData = {
                'addr': fusionVac,

                "fusionVac": "60 31 C0 E9 00 00 00 00",

                "charVac": "3B 05" + self.dbg.reverseCode(hex(wallXY)[2:])
                            + "0F 84 06 00 00 00 40 E9 26 00 00 00",

                "charXY": "A1 68 92 97 00" + "8B 98 9C 05 00 00" + "8B 88 A0 05 00 00"
                            + "B8" + self.dbg.reverseCode(hex(wallXY)[2:]) + "89 18"
                            + "89 48 04" + "89 58 08" + "89 48 0C" + "E9 00 00 00 00",

                "finalizeWV": "61" + "FF B3 E4 0C 00 00" + "FF B3 E0 0C 00 00"
                                + "E9" + self.dbg.reverseCode(hex(0x10043F497 - (fusionVac+0x52))[2:]),

                "leftWall": "DB 05" + self.dbg.reverseCode(hex(wallXY)[2:]) + "59" + "59" + "E9" + self.dbg.reverseCode(hex(0x1007F9322 - (fusionVac+0x5F))[2:]),

                "leftOFF": "DB 43 24" + "59" + "59" + "E9" + self.dbg.reverseCode(hex(0x1007F9322 - (fusionVac+0x69))[2:]),

                "rightWall": "50" + "B8" + self.dbg.reverseCode(hex(wallXY)[2:]) + "8D 40 08" + "DB 00" + "58" + "59" + "59"
                            + "E9" + self.dbg.reverseCode(hex(0x1007F9347 - (fusionVac+0x7C))[2:]),

                "rightOFF": "DB 45 08" + "59" + "59" + "E9" + self.dbg.reverseCode(hex(0x1007F9347 - (fusionVac+0x86))[2:]),

                "topWall": "50" + "B8" + self.dbg.reverseCode(hex(wallXY)[2:]) + "8D 40 04" + "DB 00" + "58 59 59"
                            + "E9" + self.dbg.reverseCode(hex(0x1007F937C - (fusionVac+0x99))[2:]),

                "topOFF": "DB 43 28" + "59 59" + "E9" + self.dbg.reverseCode(hex(0x1007F937C - (fusionVac+0xA3))[2:]),

                "bottomWall": "50" + "B8" + self.dbg.reverseCode(hex(wallXY)[2:]) + "8D 40 0C" + "DB 00"
                            + "58 59 59" + "E9" + self.dbg.reverseCode(hex(0x1007F93A4 - (fusionVac+0xB6))[2:]),

                "bottomOFF": "DB 45 08" + "59 59" + "E9" + self.dbg.reverseCode(hex(0x1007F93A4 - (fusionVac+0xC0))[2:]),

                "fly": "50" + "A1 58 83 97 00" + "8B 80 74 0D 00 00" + "83 E8 0C" + "39 F0" + "58" + "0F 84 0F 00 00 00"
                        + "39 F8" + "59 59" + "0F 85" + self.dbg.reverseCode(hex(0x1007F1CE0 - (fusionVac+0xE2))[2:])
                        + "E9" + self.dbg.reverseCode(hex(0x1007F1C10 - (fusionVac+0xE7))[2:]),

                "noFly": "39 F8" + "59 59" + "0F 84" + self.dbg.reverseCode(hex(0x1007F1CE0 - (fusionVac+0xF1))[2:])
                        + "E9" + self.dbg.reverseCode(hex(0x1007F1C10 - (fusionVac+0xF6))[2:]),

                "monsterControl": "E9" + self.dbg.reverseCode(hex(0x1007F9309 - (fusionVac+0xFB))[2:]),

                "monsterControl2": "50" + "A1 58 83 97 00" + "8B 80 74 0D 00 00" + "83 E8 0C" + "39 D8" + "58" + "0F 84 12 00 00 00"
                                    + "39 B3 5C 01 00 00" + "57" + "0F 85" + self.dbg.reverseCode(hex(0x1007F186E - (fusionVac+0x120))[2:])
                                    + "E9" + self.dbg.reverseCode(hex(0x1007F1869 - (fusionVac+0x125))[2:]),

                "noControl2": "39 B3 5C 01 00 00" + "57" + "0F 84" + self.dbg.reverseCode(hex(0x1007F186E - (fusionVac+0x132))[2:])
                            + "E9" + self.dbg.reverseCode(hex(0x1007F1869 - (fusionVac+0x137))[2:])
            }

            mainDataHack = {
                0x0043F48B: "E9" + self.dbg.reverseCode(hex(fusionVac - 0x0043F490)[2:]) + "90"*7,
                0x007F931D: "E9" + self.dbg.reverseCode(hex((fusionVac + 0x52) - 0x007F9322)[2:]),
                0x007F9342: "E9" + self.dbg.reverseCode(hex((fusionVac + 0x69) - 0x007F9347)[2:]),
                0x007F9377: "E9" + self.dbg.reverseCode(hex((fusionVac + 0x86) - 0x007F937C)[2:]),
                0x007F939F: "E9" + self.dbg.reverseCode(hex((fusionVac + 0xA3) - 0x007F93A4)[2:]),
                0x007F1C06: "E9" + self.dbg.reverseCode(hex((fusionVac + 0xC0) - 0x007F1C0B)[2:]) + "90"*5,
                0x007F92FC: "E9" + self.dbg.reverseCode(hex((fusionVac + 0xF6) - 0x007F9301)[2:]) + "90"*8,
                0x007F185A: "E9" + self.dbg.reverseCode(hex((fusionVac + 0xFB) - 0x007F185F)[2:]) + "90"*4 + "89 83 70 01 00 00",
            }

            self.dbg.write_process_memory(wallXYData["addr"], wallXYData["data"], h_process=self.h_process)
            self.dbg.write_process_memory(fusionVacData["addr"],
                                          fusionVacData["fusionVac"]
                                          + fusionVacData["charVac"]
                                          + fusionVacData["charXY"]
                                          + fusionVacData["finalizeWV"]
                                          + fusionVacData["leftWall"]
                                          + fusionVacData["leftOFF"]
                                          + fusionVacData["rightWall"]
                                          + fusionVacData["rightOFF"]
                                          + fusionVacData["topWall"]
                                          + fusionVacData["topOFF"]
                                          + fusionVacData["bottomWall"]
                                          + fusionVacData["bottomOFF"]
                                          + fusionVacData["fly"]
                                          + fusionVacData["noFly"]
                                          + fusionVacData["monsterControl"]
                                          + fusionVacData["monsterControl2"]
                                          + fusionVacData["noControl2"],
                                          h_process=self.h_process
                                          )

            for mainAddr in mainDataHack:
                self.dbg.write_process_memory(mainAddr,
                                              mainDataHack[mainAddr],
                                              h_process=self.h_process)

        else:
            mainData = {
                0x0043F48B: "FF B3 E4 0C 00 00" + "FF B3 E0 0C 00 00",
                0x007F931D: "DB 43 24" + "59"*2,
                0x007F9342: "DB 45 08" + "59"*2,
                0x007F9377: "DB 43 28" + "59"*2,
                0x007F939F: "DB 45 08" + "59"*2,
                0x007F1C06: "39 F8" + "59"*2 + "0F 84 D0 00 00 00",
                0x007F92FC: "83 BF 38 02 00 00 03" + "0F 85 62 01 00 00",
                0x007F185A: "39 B3 5C 01 00 00" + "57" + "89 83 70 01 00 00" + "74 05"
            }
            for mainAddr in mainData:
                self.dbg.write_process_memory(mainAddr, mainData[mainAddr], h_process=self.h_process)

            self.dbg.freeMem(address=self.test["fusionVac"], h_process=self.h_process)
            self.dbg.freeMem(address=self.test["wallXY"], h_process=self.h_process)
            self.test["fusionVac"] = None
            self.test["wallXY"] = None


    def dmgHack(self, active):
        if self.h_process:
            if active == "reset":
                currentDmg = {
                    0x008ECB38: self.dbg.read_process_memory(0x008ECB38, 8, h_process=self.h_process),
                    0x008ED758: self.dbg.read_process_memory(0x008ED758, 8, h_process=self.h_process),
                    0x008ECB30: self.dbg.read_process_memory(0x008ECB30, 8, h_process=self.h_process),
                    0x008ED778: self.dbg.read_process_memory(0x008ED778, 8, h_process=self.h_process)
                }

                if currentDmg != self.originalDmg:
                    for dmg in self.originalDmg:
                        self.dbg.write_process_memory(dmg, self.originalDmg[dmg], h_process=self.h_process)
                    print("Reset Dmg!")
            else:
                dmgData = dict(
                    min={"addr": 0x008ECB38, "currentDmg": ""},
                    max1={"addr": 0x008ED758, "currentDmg": ""},
                    max2={"addr": 0x008ECB30, "currentDmg": ""},
                    max3={"addr": 0x008ED778, "currentDmg": ""}
                )

                for dmg in dmgData:
                    dmgData[dmg]["currentDmg"] = self.dbg.read_process_memory(dmgData[dmg]["addr"], 8, h_process=self.h_process)

                for dmg in dmgData:
                    dmgData[dmg]["currentDmg"] = self.dbg.reverseCode(dmgData[dmg]["currentDmg"][18:])
                    dmgData[dmg]["currentDmg"] = int(dmgData[dmg]["currentDmg"].replace(" ", ""), 16)

                if "min" in active.lower():
                    if "d" in active.lower():
                        for dmg in dmgData:
                            if "min" in dmg:
                                new_dmin = dmgData[dmg]["currentDmg"] - 5
                                data_new_dmin = "00 " * 6 + self.dbg.reverseCode(hex(new_dmin)[2:])
                                self.dbg.write_process_memory(dmgData[dmg]["addr"], data_new_dmin, h_process=self.h_process)
                    else:
                        for dmg in dmgData:
                            if "min" in dmg:
                                new_dmin = dmgData[dmg]["currentDmg"] + 5
                                data_new_dmin = "00 " * 6 + self.dbg.reverseCode(hex(new_dmin)[2:])
                                self.dbg.write_process_memory(dmgData[dmg]["addr"], data_new_dmin, h_process=self.h_process)

                else:
                    if "d" in active.lower():
                        for dmg in dmgData:
                            if "max" in dmg:
                                new_dmin = dmgData[dmg]["currentDmg"] - 5
                                data_new_dmax = "00 " * 6 + self.dbg.reverseCode(hex(new_dmin)[2:])
                                self.dbg.write_process_memory(dmgData[dmg]["addr"], data_new_dmax, h_process=self.h_process)

                    else:
                        for dmg in dmgData:
                            if "max" in dmg:
                                new_dmin = dmgData[dmg]["currentDmg"] + 5
                                data_new_dmax = "00 " * 6 + self.dbg.reverseCode(hex(new_dmin)[2:])
                                self.dbg.write_process_memory(dmgData[dmg]["addr"], data_new_dmax, h_process=self.h_process)
        else:
            print("h_process is", self.h_process)


    def statis(self):
        if not self.h_process:
            return ("N/A", "N/A")

        playerPointer = 0x00978140
        playerOffset = 0x18

        mobsPointer = 0x0097813C
        mobsOffset = 0x10

        plPointerData = self.dbg.read_process_memory(playerPointer, 4, h_process=self.h_process)
        moPointerData = self.dbg.read_process_memory(mobsPointer, 4, h_process=self.h_process)
        if not plPointerData or not moPointerData:
            return ("N/A", "N/A")

        playersAddr = int(self.dbg.reverseCode(plPointerData).replace(" ", ""), 16) + playerOffset
        mobsAddr = int(self.dbg.reverseCode(moPointerData).replace(" ", ""), 16) + mobsOffset

        mobsNumber = self.dbg.read_process_memory(mobsAddr, 4, h_process=self.h_process)
        playersNumber = self.dbg.read_process_memory(playersAddr, 4, h_process=self.h_process)
        if not playersNumber or not mobsNumber:
            return ("N/A", "N/A")

        playersNumber = int(self.dbg.reverseCode(playersNumber).replace(" ", ""), 16)
        mobsNumber = int(self.dbg.reverseCode(mobsNumber).replace(" ", ""), 16)

        return playersNumber, mobsNumber


