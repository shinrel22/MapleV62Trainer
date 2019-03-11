from .debugger import Debugger


class HackingOperator(object):
    def __init__(self):
        self.debugger = Debugger()
        self.proc_name = None
        self.as_alloc_addr = None

        self.vac_alloc_addr = None
        self.cc_vac_alloc_addr = {
            "begin": None,
            "old data": None,
            "pointer": None,
            "bool": None
        }

        self.fullmap_attack_alloc_addr = None

        # Original Damage
        self.original_dmg = {
            0x008ECB38: "00 00 00 00 00 00 24 40",
            0x008ED758: "00 00 00 00 00 00 10 40",
            0x008ECB30: "00 00 00 00 00 00 14 40",
            0x008ED778: "33 33 33 33 33 33 0b 40"
        }

    def toggle_full_god_mode(self, active=None):
        data = {
            "addr": 0x007AD377,
            "data_hack": "0F 84",
            "data": "0F 85"
        }
        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_miss_god_mode(self, active=None):
        data = {
            "miss_addr": 0x007AD487,
            "data": "89 06 83 c6 04 ff 4d c0",
            "data_hack": "c7 06 00 00 00 00 90 90"
        }

        if active:
            self.debugger.write_process_memory(data["miss_addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["miss_addr"], data["data"])

    def toggle_accuracy_hack(self, active=None):
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
            "acc_addr": 0x00424D22,
            "data": "DC 0D C8 89 8E 00",
            "data_hack": "DC 0D 00 00 BD 0F"
        }

        data2 = {
            "acc_addr": 0x008ED6F8,
            "data": "66 66 66 66 66 66 E6 3F",
            "data_hack": "00 00 00 E0 CF 12 63 41"
        }

        data3 = {
            "acc_addr": 0x005DE247,
            "data": "0F 85 9A 00 00 00",
            "data_hack": "90 90 90 90 90 90"
        }
        if active:
            self.debugger.write_process_memory(data1["acc_addr"], data1["data_hack"])
            self.debugger.write_process_memory(data2["acc_addr"], data2["data_hack"])
            self.debugger.write_process_memory(data3["acc_addr"], data3["data_hack"])
        else:
            self.debugger.write_process_memory(data1["acc_addr"], data1["data"])
            self.debugger.write_process_memory(data2["acc_addr"], data2["data"])
            self.debugger.write_process_memory(data3["acc_addr"], data3["data"])

    def toggle_defense_hack(self, active=None):
        data = {
            "addr": 0x00670090,
            "data": "72 04",
            "data_hack": "77 04"
        }

        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_no_knock_back(self, active=None):
        data = {
            "addr": 0x007ADB78,
            "data": "7C 03",
            "data_hack": "7D 03"
        }

        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_unlimited_attack(self, active=None):
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
            self.debugger.write_process_memory(data1["addr"], data1["data_hack"])
            self.debugger.write_process_memory(data2["addr"], data2["data_hack"])
        else:
            self.debugger.write_process_memory(data1["addr"], data1["data"])
            self.debugger.write_process_memory(data2["addr"], data2["data"])

    def toggle_speed_attack(self, active=None):
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
                addr_alloc = self.debugger.allocate_mem(size=32)
                self.as_alloc_addr = addr_alloc
            if not addr_alloc:
                return False

            code1 = 0x100442DE4 - (addr_alloc + 0xE)
            code1 = self.debugger.reverse_code(hex(code1)[2:])

            code2 = (0x100442DE4 + 0x3) - (addr_alloc + 0x13)
            code2 = self.debugger.reverse_code(hex(code2)[2:])

            code3 = addr_alloc - 0x00442DE4
            code3 = self.debugger.reverse_code(hex(code3)[2:])

            sub_assembly_function = [
                ["base_addr", addr_alloc],
                ["mov eax,FFFF0000", "B8 00 00 FF FF"],
                ["cmp eax,02", "83 F8 02"],
                ["jg NamLun.exe+42DE4", "0F 8F" + code1],
                ["jmp NamLun.exe+42DE7", "E9" + code2]
            ]

            main_assembly_func_hack = [
                ["base_addr", 0x00442DDF],
                ["jmp <sub_assembly_function>", "E9" + code3]
            ]

            sub_data_hack = ""
            main_data_hack = ""

            for data1 in sub_assembly_function[1:]:
                sub_data_hack += data1[1]
            for data2 in main_assembly_func_hack[1:]:
                main_data_hack += data2[1]

            self.debugger.write_process_memory(sub_assembly_function[0][1], sub_data_hack)
            self.debugger.write_process_memory(main_assembly_func_hack[0][1], main_data_hack)

        else:
            main_assembly_func = [
                ["base_addr", 0x00442DDF],
                ["jg NamLun.exe+42DE4", "7f 03 6a 02 58"],
            ]

            self.debugger.write_process_memory(main_assembly_func[0][1], main_assembly_func[1][1])

    def toggle_movement_speed_hack(self, active=None):
        data = {
            "addr": 0x007F246D,
            "data": "0F 84 82 00 00 00",
            "data_hack": "90 90 90 90 90 90"
        }

        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_air_swim(self, active=None):
        data = {
            "addr": 0x00614CC7,
            "data": "75 04",
            "data_hack": "74 04"
        }

        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_tubi(self, active=None):
        data = {
            "addr": 0x004BECC6,
            "data": "75 36",
            "data_hack": "90 90"
        }

        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_mana_regen(self, active=None):
        data = {
            "addr": 0x00830420,
            "data": "81 FB 10 27",
            "data_hack": "81 FB 01 00"
        }

        if active:
            self.debugger.write_process_memory(data["addr"], data["data_hack"])
        else:
            self.debugger.write_process_memory(data["addr"], data["data"])

    def toggle_hp_hack(self, active=None):
        # Not yet
        pass

    def toggle_full_map_attack(self, active=None):
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
        if active:
            if self.fullmap_attack_alloc_addr:
                fullmap_att_addr = self.fullmap_attack_alloc_addr

            else:
                fullmap_att_addr = self.debugger.allocate_mem(size=64)
                self.fullmap_attack_alloc_addr = fullmap_att_addr

            fullmap_att_data = {
                "addr": fullmap_att_addr,
                "FMA": "8B 15 58 83 97 00" + "8D 92 5C 0D 00 00" + "8D 02"
                       + "E9" + self.debugger.reverse_code(hex(0x1005C97AD - (fullmap_att_addr + 0x13))[2:])
            }

            main_data_hack = {
                0x005C979E: "E9" + self.debugger.reverse_code(hex(fullmap_att_addr - 0x005C97A3)[2:])
            }

            self.debugger.write_process_memory(fullmap_att_data["addr"],
                                               fullmap_att_data["FMA"])
            for addr in main_data_hack:
                self.debugger.write_process_memory(addr, main_data_hack[addr])

        else:
            main_data = {
                0x005C979E: "8B 8B 80 04 00 00" + "8D 83 80 04 00 00" + "8B 40 04"
            }
            for addr in main_data:
                self.debugger.write_process_memory(addr, main_data[addr])
            if self.fullmap_attack_alloc_addr:
                self.debugger.free_mem(address=self.fullmap_attack_alloc_addr)
                self.fullmap_attack_alloc_addr = None

    def toggle_cc_vac(self, active=None):
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
            if self.cc_vac_alloc_addr["begin"]:
                begin = self.cc_vac_alloc_addr["begin"]
                old_data = self.cc_vac_alloc_addr["old_data"]
                pointer = self.cc_vac_alloc_addr["pointer"]
                booL = self.cc_vac_alloc_addr["bool"]
            else:
                begin = self.debugger.allocate_mem(size=2048)
                old_data = self.debugger.allocate_mem(size=32)
                pointer = self.debugger.allocate_mem(size=4)
                booL = self.debugger.allocate_mem(size=4)
                self.cc_vac_alloc_addr["begin"] = begin
                self.cc_vac_alloc_addr["old_data"] = old_data
                self.cc_vac_alloc_addr["pointer"] = pointer
                self.cc_vac_alloc_addr["bool"] = booL

            begin_data = {
                "addr": begin,
                "begin": "83 3D" + self.debugger.reverse_code(hex(booL)[2:]) + "01"
                         + "0F 84 0F 00 00 00" + "BE" + self.debugger.reverse_code(hex(old_data)[2:])
                         + "A5" * 4 + "5F" + "E9" + self.debugger.reverse_code(hex(0x1007F115B - (begin + 0x1C))[2:])[
                                                    :11],

                "set": "8B 35 58 83 97 00" + "8B 76 24" + "89 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "8B 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "89 35" + self.debugger.reverse_code(hex(old_data)[2:])
                       + "8B 35 58 83 97 00" + "8B 76 28"
                       + "89 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "8B 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "89 35" + self.debugger.reverse_code(hex(old_data + 0x4)[2:])
                       + "8B 35 58 83 97 00" + "8B 76 2C"
                       + "89 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "8B 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "89 35" + self.debugger.reverse_code(hex(old_data + 0x8)[2:])
                       + "8B 35 58 83 97 00" + "8B 76 30"
                       + "89 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "8B 35" + self.debugger.reverse_code(hex(pointer)[2:])
                       + "89 35" + self.debugger.reverse_code(hex(old_data + 0x2c)[2:])
                       + "C7 05" + self.debugger.reverse_code(hex(booL)[2:]) + "00" * 4
                       + "E9 76 FF FF FF"
            }

            bool_data = {
                "addr": booL,
                "bool": "01"
            }

            main_data_hack = {
                0x007F1156: "E9" + self.debugger.reverse_code(hex((begin + 0x100000000) - 0x007F115B)[2:])[:11]
            }
            print(hex(begin), hex(old_data), hex(pointer), hex(booL))
            print(self.debugger.reverse_code(hex(0x1007F115B - (begin + 0x1C))[2:])[:11],
                  self.debugger.reverse_code(hex((begin + 0x100000000) - 0x007F115B)[2:])[:11])
            self.debugger.write_process_memory(bool_data["addr"], bool_data["bool"])
            self.debugger.write_process_memory(begin_data["addr"], begin_data["begin"]
                                               + begin_data["set"])
            for addr in main_data_hack:
                self.debugger.write_process_memory(addr, main_data_hack[addr])

        else:
            main_data = {
                0x007F1156: "A5" * 4 + "5F"
            }
            for addr in main_data:
                self.debugger.write_process_memory(addr, main_data[addr])
            if self.cc_vac_alloc_addr["begin"]:
                for item in self.cc_vac_alloc_addr:
                    self.debugger.free_mem(address=self.cc_vac_alloc_addr[item])
                    self.cc_vac_alloc_addr[item] = None

    def toggle_mobs_vac(self, active=None):
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
        if active == "left" or active == "right":
            if self.vac_alloc_addr:
                vac = self.vac_alloc_addr
            else:
                vac = self.debugger.allocate_mem(size=64)
                self.vac_alloc_addr = vac

            vac_data = {
                "addr": vac,
                "vac": "83 FF 00" + "0F 84 0C 00 00 00" + "39 B3 78 01 00 00"
                       + "0F 84" + self.debugger.reverse_code(hex(0x1007F187D - (vac + 0x15))[2:]),
                "end": "E8" + self.debugger.reverse_code(hex(0x1007F1FEC - (vac + 0x1A))[2:])
                       + "E9" + self.debugger.reverse_code(hex(0x1007F186E - (vac + 0x1F))[2:])
            }
            self.debugger.write_process_memory(vac_data["addr"], vac_data["vac"]
                                               + vac_data["end"])

            main_data_hack = {
                0x007f1867: "E9" + self.debugger.reverse_code(hex(vac - 0x007F186C)[2:])
                            + "90" * 2
            }
            for addr in main_data_hack:
                self.debugger.write_process_memory(addr, main_data_hack[addr])

            left = {
                "addr": 0x007F4055,
                "data_hack": "74 53",
                "data": "73 53"
            }
            right = {
                "addr": 0x007F40C4,
                "data_hack": "77 72",
                "data": "76 72"
            }

            if "left" in active:

                self.debugger.write_process_memory(left["addr"], left["data_hack"])
                self.debugger.write_process_memory(right["addr"], right["data"])
            else:
                self.debugger.write_process_memory(right["addr"], right["data_hack"])
                self.debugger.write_process_memory(left["addr"], left["data"])

        else:
            main_data = {
                0x007f1867: "74 05" + "E8 7E 07 00 00",
                0x007F4055: "73 53",  # left
                0x007F40C4: "76 72"  # right
            }
            for addr in main_data:
                self.debugger.write_process_memory(addr, main_data[addr])
            if self.vac_alloc_addr:
                self.debugger.free_mem(address=self.vac_alloc_addr)
                self.vac_alloc_addr = None

    def adjust_damage(self, active):
        if active == "reset":
            current_dmg = {
                0x008ECB38: self.debugger.read_process_memory(0x008ECB38, 8),
                0x008ED758: self.debugger.read_process_memory(0x008ED758, 8),
                0x008ECB30: self.debugger.read_process_memory(0x008ECB30, 8),
                0x008ED778: self.debugger.read_process_memory(0x008ED778, 8)
            }

            if current_dmg != self.original_dmg:
                for dmg in self.original_dmg:
                    self.debugger.write_process_memory(dmg, self.original_dmg[dmg])
                print("Reset Dmg!")
        else:
            dmg_data = dict(
                min={"addr": 0x008ECB38, "current_dmg": ""},
                max1={"addr": 0x008ED758, "current_dmg": ""},
                max2={"addr": 0x008ECB30, "current_dmg": ""},
                max3={"addr": 0x008ED778, "current_dmg": ""}
            )

            for dmg in dmg_data:
                dmg_data[dmg]["current_dmg"] = self.debugger.read_process_memory(dmg_data[dmg]["addr"], 8)

            for dmg in dmg_data:
                dmg_data[dmg]["current_dmg"] = self.debugger.reverse_code(dmg_data[dmg]["current_dmg"][18:])
                dmg_data[dmg]["current_dmg"] = int(dmg_data[dmg]["current_dmg"].replace(" ", ""), 16)

            if "min" in active.lower():
                if "d" in active.lower():
                    for dmg in dmg_data:
                        if "min" in dmg:
                            new_dmin = dmg_data[dmg]["current_dmg"] - 5
                            data_new_dmin = "00 " * 6 + self.debugger.reverse_code(hex(new_dmin)[2:])
                            self.debugger.write_process_memory(dmg_data[dmg]["addr"], data_new_dmin)
                else:
                    for dmg in dmg_data:
                        if "min" in dmg:
                            new_dmin = dmg_data[dmg]["current_dmg"] + 5
                            data_new_dmin = "00 " * 6 + self.debugger.reverse_code(hex(new_dmin)[2:])
                            self.debugger.write_process_memory(dmg_data[dmg]["addr"], data_new_dmin)

            else:
                if "d" in active.lower():
                    for dmg in dmg_data:
                        if "max" in dmg:
                            new_dmin = dmg_data[dmg]["current_dmg"] - 5
                            data_new_dmax = "00 " * 6 + self.debugger.reverse_code(hex(new_dmin)[2:])
                            self.debugger.write_process_memory(dmg_data[dmg]["addr"], data_new_dmax)

                else:
                    for dmg in dmg_data:
                        if "max" in dmg:
                            new_dmin = dmg_data[dmg]["current_dmg"] + 5
                            data_new_dmax = "00 " * 6 + self.debugger.reverse_code(hex(new_dmin)[2:])
                            self.debugger.write_process_memory(dmg_data[dmg]["addr"], data_new_dmax)

    def get_statistic(self):
        statistics = {}

        player_pointer = 0x00978140
        player_offset = 0x18

        mobs_pointer = 0x0097813C
        mobs_offset = 0x10

        map_id_pointer = 0x00979268
        map_id_offset = 0x62C

        pl_pointer_data = self.debugger.read_process_memory(player_pointer, 4)
        if not pl_pointer_data:
            statistics["player_count"] = None
        else:
            players_addr = int(self.debugger.reverse_code(pl_pointer_data).replace(" ", ""), 16) + player_offset
            players_number = self.debugger.read_process_memory(players_addr, 4)
            players_number = int(self.debugger.reverse_code(players_number).replace(" ", ""), 16)
            statistics["player_count"] = str(players_number + 1)

        mo_pointer_data = self.debugger.read_process_memory(mobs_pointer, 4)
        if not mo_pointer_data:
            statistics["monster_count"] = None
        else:
            mobs_addr = int(self.debugger.reverse_code(mo_pointer_data).replace(" ", ""), 16) + mobs_offset
            mobs_number = self.debugger.read_process_memory(mobs_addr, 4)
            mobs_number = int(self.debugger.reverse_code(mobs_number).replace(" ", ""), 16)
            statistics["monster_count"] = str(mobs_number)

        map_pointer_data = self.debugger.read_process_memory(map_id_pointer, 4)
        if not map_pointer_data:
            statistics["map_id"] = None
        else:
            map_id_addr = int(self.debugger.reverse_code(map_pointer_data).replace(" ", ""), 16) + map_id_offset
            map_id = self.debugger.read_process_memory(map_id_addr, 4)
            map_id = int(self.debugger.reverse_code(map_id).replace(" ", ""), 16)
            statistics["map_id"] = str(map_id)

        dmg_cap_addr = 0x008ED798
        dmg_cap = self.debugger.read_process_memory(dmg_cap_addr, 4)
        if not dmg_cap:
            statistics["damage_cap"] = None
        else:
            dmg_cap = int(self.debugger.reverse_code(dmg_cap).replace(" ", ""), 16)
            statistics["damage_cap"] = str(dmg_cap)

        magic_att_cap_addr = 0x006642A7
        magic_att_cap = self.debugger.read_process_memory(magic_att_cap_addr, 4)
        if not magic_att_cap:
            statistics["magic_att_cap"] = None
        else:
            magic_att_cap = int(self.debugger.reverse_code(magic_att_cap).replace(" ", ""), 16)
            statistics["magic_att_cap"] = str(magic_att_cap)

        meso_drop_cap_addr = 0x006C150B
        meso_drop_cap = self.debugger.read_process_memory(meso_drop_cap_addr, 4)
        if not meso_drop_cap:
            statistics["meso_drop_cap"] = None
        else:
            meso_drop_cap = int(self.debugger.reverse_code(meso_drop_cap).replace(" ", ""), 16)
            statistics["meso_drop_cap"] = str(meso_drop_cap)

        return statistics
