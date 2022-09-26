using System;
using System.Runtime.InteropServices;

namespace Libpcap.Native;

internal static unsafe partial class LibpcapNative
{
    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("u_int")]
    public static extern uint bpf_filter([NativeTypeName("const struct bpf_insn *")] bpf_insn* param0, [NativeTypeName("const u_char *")] byte* param1, [NativeTypeName("u_int")] uint param2, [NativeTypeName("u_int")] uint param3);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int bpf_validate([NativeTypeName("const struct bpf_insn *")] bpf_insn* f, int len);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("char *")]
    public static extern sbyte* bpf_image([NativeTypeName("const struct bpf_insn *")] bpf_insn* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void bpf_dump([NativeTypeName("const struct bpf_program *")] bpf_program* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_init([NativeTypeName("unsigned int")] uint param0, [NativeTypeName("char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("char *")]
    [Obsolete("use 'pcap_findalldevs' and use the first devic")]
    public static extern sbyte* pcap_lookupdev([NativeTypeName("char *")] sbyte* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_lookupnet([NativeTypeName("const char *")] sbyte* param0, [NativeTypeName("bpf_u_int32 *")] uint* param1, [NativeTypeName("bpf_u_int32 *")] uint* param2, [NativeTypeName("char *")] sbyte* param3);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_create([NativeTypeName("const char *")] sbyte* param0, [NativeTypeName("char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_snaplen([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_promisc([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_can_set_rfmon([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_rfmon([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_timeout([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_tstamp_type([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_immediate_mode([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_buffer_size([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_tstamp_precision([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_get_tstamp_precision([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_activate([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_list_tstamp_types([NativeTypeName("pcap_t *")] pcap* param0, int** param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_free_tstamp_types(int* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_tstamp_type_name_to_val([NativeTypeName("const char *")] sbyte* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_tstamp_type_val_to_name(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_tstamp_type_val_to_description(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_open_live([NativeTypeName("const char *")] sbyte* param0, int param1, int param2, int param3, [NativeTypeName("char *")] sbyte* param4);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_open_dead(int param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_open_dead_with_tstamp_precision(int param0, int param1, [NativeTypeName("u_int")] uint param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_open_offline_with_tstamp_precision([NativeTypeName("const char *")] sbyte* param0, [NativeTypeName("u_int")] uint param1, [NativeTypeName("char *")] sbyte* param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_open_offline([NativeTypeName("const char *")] sbyte* param0, [NativeTypeName("char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_hopen_offline_with_tstamp_precision([NativeTypeName("intptr_t")] nint param0, [NativeTypeName("u_int")] uint param1, [NativeTypeName("char *")] sbyte* param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_hopen_offline([NativeTypeName("intptr_t")] nint param0, [NativeTypeName("char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_close([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_loop([NativeTypeName("pcap_t *")] pcap* param0, int param1, [NativeTypeName("pcap_handler")] delegate* unmanaged[Cdecl]<byte*, pcap_pkthdr*, byte*, void> param2, [NativeTypeName("u_char *")] byte* param3);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_dispatch([NativeTypeName("pcap_t *")] pcap* param0, int param1, [NativeTypeName("pcap_handler")] delegate* unmanaged[Cdecl]<byte*, pcap_pkthdr*, byte*, void> param2, [NativeTypeName("u_char *")] byte* param3);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const u_char *")]
    public static extern byte* pcap_next([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("struct pcap_pkthdr *")] pcap_pkthdr* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_next_ex([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("struct pcap_pkthdr **")] pcap_pkthdr** param1, [NativeTypeName("const u_char **")] byte** param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_breakloop([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_stats([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("struct pcap_stat *")] pcap_stat* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setfilter([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("struct bpf_program *")] bpf_program* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setdirection([NativeTypeName("pcap_t *")] pcap* param0, pcap_direction_t param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_getnonblock([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setnonblock([NativeTypeName("pcap_t *")] pcap* param0, int param1, [NativeTypeName("char *")] sbyte* param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_inject([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("const void *")] void* param1, [NativeTypeName("size_t")] nuint param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_sendpacket([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("const u_char *")] byte* param1, int param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_statustostr(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_strerror(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("char *")]
    public static extern sbyte* pcap_geterr([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_perror([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("const char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_compile([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("struct bpf_program *")] bpf_program* param1, [NativeTypeName("const char *")] sbyte* param2, int param3, [NativeTypeName("bpf_u_int32")] uint param4);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_compile_nopcap(int param0, int param1, [NativeTypeName("struct bpf_program *")] bpf_program* param2, [NativeTypeName("const char *")] sbyte* param3, int param4, [NativeTypeName("bpf_u_int32")] uint param5);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_freecode([NativeTypeName("struct bpf_program *")] bpf_program* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_offline_filter([NativeTypeName("const struct bpf_program *")] bpf_program* param0, [NativeTypeName("const struct pcap_pkthdr *")] pcap_pkthdr* param1, [NativeTypeName("const u_char *")] byte* param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_datalink([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_datalink_ext([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_list_datalinks([NativeTypeName("pcap_t *")] pcap* param0, int** param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_set_datalink([NativeTypeName("pcap_t *")] pcap* param0, int param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_free_datalinks(int* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_datalink_name_to_val([NativeTypeName("const char *")] sbyte* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_datalink_val_to_name(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_datalink_val_to_description(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_datalink_val_to_description_or_dlt(int param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_snapshot([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_is_swapped([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_major_version([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_minor_version([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_bufsize([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("FILE *")]
    public static extern _iobuf* pcap_file([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [Obsolete("use 'pcap_handle")]
    public static extern int pcap_fileno([NativeTypeName("pcap_t *")] pcap* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_wsockinit();

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_dumper_t *")]
    public static extern pcap_dumper* pcap_dump_open([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("const char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_dumper_t *")]
    public static extern pcap_dumper* pcap_dump_hopen([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("intptr_t")] nint param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_dumper_t *")]
    public static extern pcap_dumper* pcap_dump_open_append([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("const char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("FILE *")]
    public static extern _iobuf* pcap_dump_file([NativeTypeName("pcap_dumper_t *")] pcap_dumper* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("long")]
    public static extern int pcap_dump_ftell([NativeTypeName("pcap_dumper_t *")] pcap_dumper* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("int64_t")]
    public static extern long pcap_dump_ftell64([NativeTypeName("pcap_dumper_t *")] pcap_dumper* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_dump_flush([NativeTypeName("pcap_dumper_t *")] pcap_dumper* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_dump_close([NativeTypeName("pcap_dumper_t *")] pcap_dumper* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_dump([NativeTypeName("u_char *")] byte* param0, [NativeTypeName("const struct pcap_pkthdr *")] pcap_pkthdr* param1, [NativeTypeName("const u_char *")] byte* param2);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_findalldevs([NativeTypeName("pcap_if_t **")] pcap_if** param0, [NativeTypeName("char *")] sbyte* param1);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_freealldevs([NativeTypeName("pcap_if_t *")] pcap_if* param0);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("const char *")]
    public static extern sbyte* pcap_lib_version();

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setbuff([NativeTypeName("pcap_t *")] pcap* p, int dim);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setmode([NativeTypeName("pcap_t *")] pcap* p, int mode);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setmintocopy([NativeTypeName("pcap_t *")] pcap* p, int size);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("HANDLE")]
    public static extern void* pcap_getevent([NativeTypeName("pcap_t *")] pcap* p);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_oid_get_request([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("bpf_u_int32")] uint param1, void* param2, [NativeTypeName("size_t *")] nuint* param3);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_oid_set_request([NativeTypeName("pcap_t *")] pcap* param0, [NativeTypeName("bpf_u_int32")] uint param1, [NativeTypeName("const void *")] void* param2, [NativeTypeName("size_t *")] nuint* param3);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern pcap_send_queue* pcap_sendqueue_alloc([NativeTypeName("u_int")] uint memsize);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_sendqueue_destroy(pcap_send_queue* queue);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_sendqueue_queue(pcap_send_queue* queue, [NativeTypeName("const struct pcap_pkthdr *")] pcap_pkthdr* pkt_header, [NativeTypeName("const u_char *")] byte* pkt_data);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("u_int")]
    public static extern uint pcap_sendqueue_transmit([NativeTypeName("pcap_t *")] pcap* p, pcap_send_queue* queue, int sync);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("struct pcap_stat *")]
    public static extern pcap_stat* pcap_stats_ex([NativeTypeName("pcap_t *")] pcap* p, int* pcap_stat_size);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_setuserbuffer([NativeTypeName("pcap_t *")] pcap* p, int size);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_live_dump([NativeTypeName("pcap_t *")] pcap* p, [NativeTypeName("char *")] sbyte* filename, int maxsize, int maxpacks);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_live_dump_ended([NativeTypeName("pcap_t *")] pcap* p, int sync);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_start_oem([NativeTypeName("char *")] sbyte* err_str, int flags);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("PAirpcapHandle")]
    public static extern _AirpcapHandle* pcap_get_airpcap_handle([NativeTypeName("pcap_t *")] pcap* p);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("pcap_t *")]
    public static extern pcap* pcap_open([NativeTypeName("const char *")] sbyte* source, int snaplen, int flags, int read_timeout, [NativeTypeName("struct pcap_rmtauth *")] pcap_rmtauth* auth, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_createsrcstr([NativeTypeName("char *")] sbyte* source, int type, [NativeTypeName("const char *")] sbyte* host, [NativeTypeName("const char *")] sbyte* port, [NativeTypeName("const char *")] sbyte* name, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_parsesrcstr([NativeTypeName("const char *")] sbyte* source, int* type, [NativeTypeName("char *")] sbyte* host, [NativeTypeName("char *")] sbyte* port, [NativeTypeName("char *")] sbyte* name, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_findalldevs_ex([NativeTypeName("const char *")] sbyte* source, [NativeTypeName("struct pcap_rmtauth *")] pcap_rmtauth* auth, [NativeTypeName("pcap_if_t **")] pcap_if** alldevs, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("struct pcap_samp *")]
    public static extern pcap_samp* pcap_setsampling([NativeTypeName("pcap_t *")] pcap* p);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("SOCKET")]
    public static extern ulong pcap_remoteact_accept([NativeTypeName("const char *")] sbyte* address, [NativeTypeName("const char *")] sbyte* port, [NativeTypeName("const char *")] sbyte* hostlist, [NativeTypeName("char *")] sbyte* connectinghost, [NativeTypeName("struct pcap_rmtauth *")] pcap_rmtauth* auth, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: NativeTypeName("SOCKET")]
    public static extern ulong pcap_remoteact_accept_ex([NativeTypeName("const char *")] sbyte* address, [NativeTypeName("const char *")] sbyte* port, [NativeTypeName("const char *")] sbyte* hostlist, [NativeTypeName("char *")] sbyte* connectinghost, [NativeTypeName("struct pcap_rmtauth *")] pcap_rmtauth* auth, int uses_ssl, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_remoteact_list([NativeTypeName("char *")] sbyte* hostlist, [NativeTypeName("char")] sbyte sep, int size, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int pcap_remoteact_close([NativeTypeName("const char *")] sbyte* host, [NativeTypeName("char *")] sbyte* errbuf);

    [DllImport("pcap", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void pcap_remoteact_cleanup();

    [NativeTypeName("#define DLT_NULL 0")]
    public const int DLT_NULL = 0;

    [NativeTypeName("#define DLT_EN10MB 1")]
    public const int DLT_EN10MB = 1;

    [NativeTypeName("#define DLT_EN3MB 2")]
    public const int DLT_EN3MB = 2;

    [NativeTypeName("#define DLT_AX25 3")]
    public const int DLT_AX25 = 3;

    [NativeTypeName("#define DLT_PRONET 4")]
    public const int DLT_PRONET = 4;

    [NativeTypeName("#define DLT_CHAOS 5")]
    public const int DLT_CHAOS = 5;

    [NativeTypeName("#define DLT_IEEE802 6")]
    public const int DLT_IEEE802 = 6;

    [NativeTypeName("#define DLT_ARCNET 7")]
    public const int DLT_ARCNET = 7;

    [NativeTypeName("#define DLT_SLIP 8")]
    public const int DLT_SLIP = 8;

    [NativeTypeName("#define DLT_PPP 9")]
    public const int DLT_PPP = 9;

    [NativeTypeName("#define DLT_FDDI 10")]
    public const int DLT_FDDI = 10;

    [NativeTypeName("#define DLT_ATM_RFC1483 11")]
    public const int DLT_ATM_RFC1483 = 11;

    [NativeTypeName("#define DLT_RAW 12")]
    public const int DLT_RAW = 12;

    [NativeTypeName("#define DLT_SLIP_BSDOS 15")]
    public const int DLT_SLIP_BSDOS = 15;

    [NativeTypeName("#define DLT_PPP_BSDOS 16")]
    public const int DLT_PPP_BSDOS = 16;

    [NativeTypeName("#define DLT_ATM_CLIP 19")]
    public const int DLT_ATM_CLIP = 19;

    [NativeTypeName("#define DLT_REDBACK_SMARTEDGE 32")]
    public const int DLT_REDBACK_SMARTEDGE = 32;

    [NativeTypeName("#define DLT_PPP_SERIAL 50")]
    public const int DLT_PPP_SERIAL = 50;

    [NativeTypeName("#define DLT_PPP_ETHER 51")]
    public const int DLT_PPP_ETHER = 51;

    [NativeTypeName("#define DLT_SYMANTEC_FIREWALL 99")]
    public const int DLT_SYMANTEC_FIREWALL = 99;

    [NativeTypeName("#define DLT_MATCHING_MIN 104")]
    public const int DLT_MATCHING_MIN = 104;

    [NativeTypeName("#define DLT_C_HDLC 104")]
    public const int DLT_C_HDLC = 104;

    [NativeTypeName("#define DLT_CHDLC DLT_C_HDLC")]
    public const int DLT_CHDLC = 104;

    [NativeTypeName("#define DLT_IEEE802_11 105")]
    public const int DLT_IEEE802_11 = 105;

    [NativeTypeName("#define DLT_FRELAY 107")]
    public const int DLT_FRELAY = 107;

    [NativeTypeName("#define DLT_LOOP 108")]
    public const int DLT_LOOP = 108;

    [NativeTypeName("#define DLT_ENC 109")]
    public const int DLT_ENC = 109;

    [NativeTypeName("#define DLT_LINUX_SLL 113")]
    public const int DLT_LINUX_SLL = 113;

    [NativeTypeName("#define DLT_LTALK 114")]
    public const int DLT_LTALK = 114;

    [NativeTypeName("#define DLT_ECONET 115")]
    public const int DLT_ECONET = 115;

    [NativeTypeName("#define DLT_IPFILTER 116")]
    public const int DLT_IPFILTER = 116;

    [NativeTypeName("#define DLT_PFLOG 117")]
    public const int DLT_PFLOG = 117;

    [NativeTypeName("#define DLT_CISCO_IOS 118")]
    public const int DLT_CISCO_IOS = 118;

    [NativeTypeName("#define DLT_PRISM_HEADER 119")]
    public const int DLT_PRISM_HEADER = 119;

    [NativeTypeName("#define DLT_AIRONET_HEADER 120")]
    public const int DLT_AIRONET_HEADER = 120;

    [NativeTypeName("#define DLT_HHDLC 121")]
    public const int DLT_HHDLC = 121;

    [NativeTypeName("#define DLT_IP_OVER_FC 122")]
    public const int DLT_IP_OVER_FC = 122;

    [NativeTypeName("#define DLT_SUNATM 123")]
    public const int DLT_SUNATM = 123;

    [NativeTypeName("#define DLT_RIO 124")]
    public const int DLT_RIO = 124;

    [NativeTypeName("#define DLT_PCI_EXP 125")]
    public const int DLT_PCI_EXP = 125;

    [NativeTypeName("#define DLT_AURORA 126")]
    public const int DLT_AURORA = 126;

    [NativeTypeName("#define DLT_IEEE802_11_RADIO 127")]
    public const int DLT_IEEE802_11_RADIO = 127;

    [NativeTypeName("#define DLT_TZSP 128")]
    public const int DLT_TZSP = 128;

    [NativeTypeName("#define DLT_ARCNET_LINUX 129")]
    public const int DLT_ARCNET_LINUX = 129;

    [NativeTypeName("#define DLT_JUNIPER_MLPPP 130")]
    public const int DLT_JUNIPER_MLPPP = 130;

    [NativeTypeName("#define DLT_JUNIPER_MLFR 131")]
    public const int DLT_JUNIPER_MLFR = 131;

    [NativeTypeName("#define DLT_JUNIPER_ES 132")]
    public const int DLT_JUNIPER_ES = 132;

    [NativeTypeName("#define DLT_JUNIPER_GGSN 133")]
    public const int DLT_JUNIPER_GGSN = 133;

    [NativeTypeName("#define DLT_JUNIPER_MFR 134")]
    public const int DLT_JUNIPER_MFR = 134;

    [NativeTypeName("#define DLT_JUNIPER_ATM2 135")]
    public const int DLT_JUNIPER_ATM2 = 135;

    [NativeTypeName("#define DLT_JUNIPER_SERVICES 136")]
    public const int DLT_JUNIPER_SERVICES = 136;

    [NativeTypeName("#define DLT_JUNIPER_ATM1 137")]
    public const int DLT_JUNIPER_ATM1 = 137;

    [NativeTypeName("#define DLT_APPLE_IP_OVER_IEEE1394 138")]
    public const int DLT_APPLE_IP_OVER_IEEE1394 = 138;

    [NativeTypeName("#define DLT_MTP2_WITH_PHDR 139")]
    public const int DLT_MTP2_WITH_PHDR = 139;

    [NativeTypeName("#define DLT_MTP2 140")]
    public const int DLT_MTP2 = 140;

    [NativeTypeName("#define DLT_MTP3 141")]
    public const int DLT_MTP3 = 141;

    [NativeTypeName("#define DLT_SCCP 142")]
    public const int DLT_SCCP = 142;

    [NativeTypeName("#define DLT_DOCSIS 143")]
    public const int DLT_DOCSIS = 143;

    [NativeTypeName("#define DLT_LINUX_IRDA 144")]
    public const int DLT_LINUX_IRDA = 144;

    [NativeTypeName("#define DLT_IBM_SP 145")]
    public const int DLT_IBM_SP = 145;

    [NativeTypeName("#define DLT_IBM_SN 146")]
    public const int DLT_IBM_SN = 146;

    [NativeTypeName("#define DLT_USER0 147")]
    public const int DLT_USER0 = 147;

    [NativeTypeName("#define DLT_USER1 148")]
    public const int DLT_USER1 = 148;

    [NativeTypeName("#define DLT_USER2 149")]
    public const int DLT_USER2 = 149;

    [NativeTypeName("#define DLT_USER3 150")]
    public const int DLT_USER3 = 150;

    [NativeTypeName("#define DLT_USER4 151")]
    public const int DLT_USER4 = 151;

    [NativeTypeName("#define DLT_USER5 152")]
    public const int DLT_USER5 = 152;

    [NativeTypeName("#define DLT_USER6 153")]
    public const int DLT_USER6 = 153;

    [NativeTypeName("#define DLT_USER7 154")]
    public const int DLT_USER7 = 154;

    [NativeTypeName("#define DLT_USER8 155")]
    public const int DLT_USER8 = 155;

    [NativeTypeName("#define DLT_USER9 156")]
    public const int DLT_USER9 = 156;

    [NativeTypeName("#define DLT_USER10 157")]
    public const int DLT_USER10 = 157;

    [NativeTypeName("#define DLT_USER11 158")]
    public const int DLT_USER11 = 158;

    [NativeTypeName("#define DLT_USER12 159")]
    public const int DLT_USER12 = 159;

    [NativeTypeName("#define DLT_USER13 160")]
    public const int DLT_USER13 = 160;

    [NativeTypeName("#define DLT_USER14 161")]
    public const int DLT_USER14 = 161;

    [NativeTypeName("#define DLT_USER15 162")]
    public const int DLT_USER15 = 162;

    [NativeTypeName("#define DLT_IEEE802_11_RADIO_AVS 163")]
    public const int DLT_IEEE802_11_RADIO_AVS = 163;

    [NativeTypeName("#define DLT_JUNIPER_MONITOR 164")]
    public const int DLT_JUNIPER_MONITOR = 164;

    [NativeTypeName("#define DLT_BACNET_MS_TP 165")]
    public const int DLT_BACNET_MS_TP = 165;

    [NativeTypeName("#define DLT_PPP_PPPD 166")]
    public const int DLT_PPP_PPPD = 166;

    [NativeTypeName("#define DLT_PPP_WITH_DIRECTION DLT_PPP_PPPD")]
    public const int DLT_PPP_WITH_DIRECTION = 166;

    [NativeTypeName("#define DLT_LINUX_PPP_WITHDIRECTION DLT_PPP_PPPD")]
    public const int DLT_LINUX_PPP_WITHDIRECTION = 166;

    [NativeTypeName("#define DLT_JUNIPER_PPPOE 167")]
    public const int DLT_JUNIPER_PPPOE = 167;

    [NativeTypeName("#define DLT_JUNIPER_PPPOE_ATM 168")]
    public const int DLT_JUNIPER_PPPOE_ATM = 168;

    [NativeTypeName("#define DLT_GPRS_LLC 169")]
    public const int DLT_GPRS_LLC = 169;

    [NativeTypeName("#define DLT_GPF_T 170")]
    public const int DLT_GPF_T = 170;

    [NativeTypeName("#define DLT_GPF_F 171")]
    public const int DLT_GPF_F = 171;

    [NativeTypeName("#define DLT_GCOM_T1E1 172")]
    public const int DLT_GCOM_T1E1 = 172;

    [NativeTypeName("#define DLT_GCOM_SERIAL 173")]
    public const int DLT_GCOM_SERIAL = 173;

    [NativeTypeName("#define DLT_JUNIPER_PIC_PEER 174")]
    public const int DLT_JUNIPER_PIC_PEER = 174;

    [NativeTypeName("#define DLT_ERF_ETH 175")]
    public const int DLT_ERF_ETH = 175;

    [NativeTypeName("#define DLT_ERF_POS 176")]
    public const int DLT_ERF_POS = 176;

    [NativeTypeName("#define DLT_LINUX_LAPD 177")]
    public const int DLT_LINUX_LAPD = 177;

    [NativeTypeName("#define DLT_JUNIPER_ETHER 178")]
    public const int DLT_JUNIPER_ETHER = 178;

    [NativeTypeName("#define DLT_JUNIPER_PPP 179")]
    public const int DLT_JUNIPER_PPP = 179;

    [NativeTypeName("#define DLT_JUNIPER_FRELAY 180")]
    public const int DLT_JUNIPER_FRELAY = 180;

    [NativeTypeName("#define DLT_JUNIPER_CHDLC 181")]
    public const int DLT_JUNIPER_CHDLC = 181;

    [NativeTypeName("#define DLT_MFR 182")]
    public const int DLT_MFR = 182;

    [NativeTypeName("#define DLT_JUNIPER_VP 183")]
    public const int DLT_JUNIPER_VP = 183;

    [NativeTypeName("#define DLT_A429 184")]
    public const int DLT_A429 = 184;

    [NativeTypeName("#define DLT_A653_ICM 185")]
    public const int DLT_A653_ICM = 185;

    [NativeTypeName("#define DLT_USB_FREEBSD 186")]
    public const int DLT_USB_FREEBSD = 186;

    [NativeTypeName("#define DLT_USB 186")]
    public const int DLT_USB = 186;

    [NativeTypeName("#define DLT_BLUETOOTH_HCI_H4 187")]
    public const int DLT_BLUETOOTH_HCI_H4 = 187;

    [NativeTypeName("#define DLT_IEEE802_16_MAC_CPS 188")]
    public const int DLT_IEEE802_16_MAC_CPS = 188;

    [NativeTypeName("#define DLT_USB_LINUX 189")]
    public const int DLT_USB_LINUX = 189;

    [NativeTypeName("#define DLT_CAN20B 190")]
    public const int DLT_CAN20B = 190;

    [NativeTypeName("#define DLT_IEEE802_15_4_LINUX 191")]
    public const int DLT_IEEE802_15_4_LINUX = 191;

    [NativeTypeName("#define DLT_PPI 192")]
    public const int DLT_PPI = 192;

    [NativeTypeName("#define DLT_IEEE802_16_MAC_CPS_RADIO 193")]
    public const int DLT_IEEE802_16_MAC_CPS_RADIO = 193;

    [NativeTypeName("#define DLT_JUNIPER_ISM 194")]
    public const int DLT_JUNIPER_ISM = 194;

    [NativeTypeName("#define DLT_IEEE802_15_4_WITHFCS 195")]
    public const int DLT_IEEE802_15_4_WITHFCS = 195;

    [NativeTypeName("#define DLT_IEEE802_15_4 DLT_IEEE802_15_4_WITHFCS")]
    public const int DLT_IEEE802_15_4 = 195;

    [NativeTypeName("#define DLT_SITA 196")]
    public const int DLT_SITA = 196;

    [NativeTypeName("#define DLT_ERF 197")]
    public const int DLT_ERF = 197;

    [NativeTypeName("#define DLT_RAIF1 198")]
    public const int DLT_RAIF1 = 198;

    [NativeTypeName("#define DLT_IPMB_KONTRON 199")]
    public const int DLT_IPMB_KONTRON = 199;

    [NativeTypeName("#define DLT_JUNIPER_ST 200")]
    public const int DLT_JUNIPER_ST = 200;

    [NativeTypeName("#define DLT_BLUETOOTH_HCI_H4_WITH_PHDR 201")]
    public const int DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201;

    [NativeTypeName("#define DLT_AX25_KISS 202")]
    public const int DLT_AX25_KISS = 202;

    [NativeTypeName("#define DLT_LAPD 203")]
    public const int DLT_LAPD = 203;

    [NativeTypeName("#define DLT_PPP_WITH_DIR 204")]
    public const int DLT_PPP_WITH_DIR = 204;

    [NativeTypeName("#define DLT_C_HDLC_WITH_DIR 205")]
    public const int DLT_C_HDLC_WITH_DIR = 205;

    [NativeTypeName("#define DLT_FRELAY_WITH_DIR 206")]
    public const int DLT_FRELAY_WITH_DIR = 206;

    [NativeTypeName("#define DLT_LAPB_WITH_DIR 207")]
    public const int DLT_LAPB_WITH_DIR = 207;

    [NativeTypeName("#define DLT_IPMB_LINUX 209")]
    public const int DLT_IPMB_LINUX = 209;

    [NativeTypeName("#define DLT_FLEXRAY 210")]
    public const int DLT_FLEXRAY = 210;

    [NativeTypeName("#define DLT_MOST 211")]
    public const int DLT_MOST = 211;

    [NativeTypeName("#define DLT_LIN 212")]
    public const int DLT_LIN = 212;

    [NativeTypeName("#define DLT_X2E_SERIAL 213")]
    public const int DLT_X2E_SERIAL = 213;

    [NativeTypeName("#define DLT_X2E_XORAYA 214")]
    public const int DLT_X2E_XORAYA = 214;

    [NativeTypeName("#define DLT_IEEE802_15_4_NONASK_PHY 215")]
    public const int DLT_IEEE802_15_4_NONASK_PHY = 215;

    [NativeTypeName("#define DLT_LINUX_EVDEV 216")]
    public const int DLT_LINUX_EVDEV = 216;

    [NativeTypeName("#define DLT_GSMTAP_UM 217")]
    public const int DLT_GSMTAP_UM = 217;

    [NativeTypeName("#define DLT_GSMTAP_ABIS 218")]
    public const int DLT_GSMTAP_ABIS = 218;

    [NativeTypeName("#define DLT_MPLS 219")]
    public const int DLT_MPLS = 219;

    [NativeTypeName("#define DLT_USB_LINUX_MMAPPED 220")]
    public const int DLT_USB_LINUX_MMAPPED = 220;

    [NativeTypeName("#define DLT_DECT 221")]
    public const int DLT_DECT = 221;

    [NativeTypeName("#define DLT_AOS 222")]
    public const int DLT_AOS = 222;

    [NativeTypeName("#define DLT_WIHART 223")]
    public const int DLT_WIHART = 223;

    [NativeTypeName("#define DLT_FC_2 224")]
    public const int DLT_FC_2 = 224;

    [NativeTypeName("#define DLT_FC_2_WITH_FRAME_DELIMS 225")]
    public const int DLT_FC_2_WITH_FRAME_DELIMS = 225;

    [NativeTypeName("#define DLT_IPNET 226")]
    public const int DLT_IPNET = 226;

    [NativeTypeName("#define DLT_CAN_SOCKETCAN 227")]
    public const int DLT_CAN_SOCKETCAN = 227;

    [NativeTypeName("#define DLT_IPV4 228")]
    public const int DLT_IPV4 = 228;

    [NativeTypeName("#define DLT_IPV6 229")]
    public const int DLT_IPV6 = 229;

    [NativeTypeName("#define DLT_IEEE802_15_4_NOFCS 230")]
    public const int DLT_IEEE802_15_4_NOFCS = 230;

    [NativeTypeName("#define DLT_DBUS 231")]
    public const int DLT_DBUS = 231;

    [NativeTypeName("#define DLT_JUNIPER_VS 232")]
    public const int DLT_JUNIPER_VS = 232;

    [NativeTypeName("#define DLT_JUNIPER_SRX_E2E 233")]
    public const int DLT_JUNIPER_SRX_E2E = 233;

    [NativeTypeName("#define DLT_JUNIPER_FIBRECHANNEL 234")]
    public const int DLT_JUNIPER_FIBRECHANNEL = 234;

    [NativeTypeName("#define DLT_DVB_CI 235")]
    public const int DLT_DVB_CI = 235;

    [NativeTypeName("#define DLT_MUX27010 236")]
    public const int DLT_MUX27010 = 236;

    [NativeTypeName("#define DLT_STANAG_5066_D_PDU 237")]
    public const int DLT_STANAG_5066_D_PDU = 237;

    [NativeTypeName("#define DLT_JUNIPER_ATM_CEMIC 238")]
    public const int DLT_JUNIPER_ATM_CEMIC = 238;

    [NativeTypeName("#define DLT_NFLOG 239")]
    public const int DLT_NFLOG = 239;

    [NativeTypeName("#define DLT_NETANALYZER 240")]
    public const int DLT_NETANALYZER = 240;

    [NativeTypeName("#define DLT_NETANALYZER_TRANSPARENT 241")]
    public const int DLT_NETANALYZER_TRANSPARENT = 241;

    [NativeTypeName("#define DLT_IPOIB 242")]
    public const int DLT_IPOIB = 242;

    [NativeTypeName("#define DLT_MPEG_2_TS 243")]
    public const int DLT_MPEG_2_TS = 243;

    [NativeTypeName("#define DLT_NG40 244")]
    public const int DLT_NG40 = 244;

    [NativeTypeName("#define DLT_NFC_LLCP 245")]
    public const int DLT_NFC_LLCP = 245;

    [NativeTypeName("#define DLT_PFSYNC 246")]
    public const int DLT_PFSYNC = 246;

    [NativeTypeName("#define DLT_INFINIBAND 247")]
    public const int DLT_INFINIBAND = 247;

    [NativeTypeName("#define DLT_SCTP 248")]
    public const int DLT_SCTP = 248;

    [NativeTypeName("#define DLT_USBPCAP 249")]
    public const int DLT_USBPCAP = 249;

    [NativeTypeName("#define DLT_RTAC_SERIAL 250")]
    public const int DLT_RTAC_SERIAL = 250;

    [NativeTypeName("#define DLT_BLUETOOTH_LE_LL 251")]
    public const int DLT_BLUETOOTH_LE_LL = 251;

    [NativeTypeName("#define DLT_WIRESHARK_UPPER_PDU 252")]
    public const int DLT_WIRESHARK_UPPER_PDU = 252;

    [NativeTypeName("#define DLT_NETLINK 253")]
    public const int DLT_NETLINK = 253;

    [NativeTypeName("#define DLT_BLUETOOTH_LINUX_MONITOR 254")]
    public const int DLT_BLUETOOTH_LINUX_MONITOR = 254;

    [NativeTypeName("#define DLT_BLUETOOTH_BREDR_BB 255")]
    public const int DLT_BLUETOOTH_BREDR_BB = 255;

    [NativeTypeName("#define DLT_BLUETOOTH_LE_LL_WITH_PHDR 256")]
    public const int DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256;

    [NativeTypeName("#define DLT_PROFIBUS_DL 257")]
    public const int DLT_PROFIBUS_DL = 257;

    [NativeTypeName("#define DLT_PKTAP 258")]
    public const int DLT_PKTAP = 258;

    [NativeTypeName("#define DLT_EPON 259")]
    public const int DLT_EPON = 259;

    [NativeTypeName("#define DLT_IPMI_HPM_2 260")]
    public const int DLT_IPMI_HPM_2 = 260;

    [NativeTypeName("#define DLT_ZWAVE_R1_R2 261")]
    public const int DLT_ZWAVE_R1_R2 = 261;

    [NativeTypeName("#define DLT_ZWAVE_R3 262")]
    public const int DLT_ZWAVE_R3 = 262;

    [NativeTypeName("#define DLT_WATTSTOPPER_DLM 263")]
    public const int DLT_WATTSTOPPER_DLM = 263;

    [NativeTypeName("#define DLT_ISO_14443 264")]
    public const int DLT_ISO_14443 = 264;

    [NativeTypeName("#define DLT_RDS 265")]
    public const int DLT_RDS = 265;

    [NativeTypeName("#define DLT_USB_DARWIN 266")]
    public const int DLT_USB_DARWIN = 266;

    [NativeTypeName("#define DLT_OPENFLOW 267")]
    public const int DLT_OPENFLOW = 267;

    [NativeTypeName("#define DLT_SDLC 268")]
    public const int DLT_SDLC = 268;

    [NativeTypeName("#define DLT_TI_LLN_SNIFFER 269")]
    public const int DLT_TI_LLN_SNIFFER = 269;

    [NativeTypeName("#define DLT_LORATAP 270")]
    public const int DLT_LORATAP = 270;

    [NativeTypeName("#define DLT_VSOCK 271")]
    public const int DLT_VSOCK = 271;

    [NativeTypeName("#define DLT_NORDIC_BLE 272")]
    public const int DLT_NORDIC_BLE = 272;

    [NativeTypeName("#define DLT_DOCSIS31_XRA31 273")]
    public const int DLT_DOCSIS31_XRA31 = 273;

    [NativeTypeName("#define DLT_ETHERNET_MPACKET 274")]
    public const int DLT_ETHERNET_MPACKET = 274;

    [NativeTypeName("#define DLT_DISPLAYPORT_AUX 275")]
    public const int DLT_DISPLAYPORT_AUX = 275;

    [NativeTypeName("#define DLT_LINUX_SLL2 276")]
    public const int DLT_LINUX_SLL2 = 276;

    [NativeTypeName("#define DLT_SERCOS_MONITOR 277")]
    public const int DLT_SERCOS_MONITOR = 277;

    [NativeTypeName("#define DLT_OPENVIZSLA 278")]
    public const int DLT_OPENVIZSLA = 278;

    [NativeTypeName("#define DLT_EBHSCR 279")]
    public const int DLT_EBHSCR = 279;

    [NativeTypeName("#define DLT_VPP_DISPATCH 280")]
    public const int DLT_VPP_DISPATCH = 280;

    [NativeTypeName("#define DLT_DSA_TAG_BRCM 281")]
    public const int DLT_DSA_TAG_BRCM = 281;

    [NativeTypeName("#define DLT_DSA_TAG_BRCM_PREPEND 282")]
    public const int DLT_DSA_TAG_BRCM_PREPEND = 282;

    [NativeTypeName("#define DLT_IEEE802_15_4_TAP 283")]
    public const int DLT_IEEE802_15_4_TAP = 283;

    [NativeTypeName("#define DLT_DSA_TAG_DSA 284")]
    public const int DLT_DSA_TAG_DSA = 284;

    [NativeTypeName("#define DLT_DSA_TAG_EDSA 285")]
    public const int DLT_DSA_TAG_EDSA = 285;

    [NativeTypeName("#define DLT_ELEE 286")]
    public const int DLT_ELEE = 286;

    [NativeTypeName("#define DLT_Z_WAVE_SERIAL 287")]
    public const int DLT_Z_WAVE_SERIAL = 287;

    [NativeTypeName("#define DLT_USB_2_0 288")]
    public const int DLT_USB_2_0 = 288;

    [NativeTypeName("#define DLT_ATSC_ALP 289")]
    public const int DLT_ATSC_ALP = 289;

    [NativeTypeName("#define DLT_MATCHING_MAX 289")]
    public const int DLT_MATCHING_MAX = 289;

    [NativeTypeName("#define DLT_CLASS_NETBSD_RAWAF 0x02240000")]
    public const int DLT_CLASS_NETBSD_RAWAF = 0x02240000;

    [NativeTypeName("#define BPF_RELEASE 199606")]
    public const int BPF_RELEASE = 199606;

    [NativeTypeName("#define BPF_ALIGNMENT sizeof(bpf_int32)")]
    public const ulong BPF_ALIGNMENT = 4;

    [NativeTypeName("#define BPF_LD 0x00")]
    public const int BPF_LD = 0x00;

    [NativeTypeName("#define BPF_LDX 0x01")]
    public const int BPF_LDX = 0x01;

    [NativeTypeName("#define BPF_ST 0x02")]
    public const int BPF_ST = 0x02;

    [NativeTypeName("#define BPF_STX 0x03")]
    public const int BPF_STX = 0x03;

    [NativeTypeName("#define BPF_ALU 0x04")]
    public const int BPF_ALU = 0x04;

    [NativeTypeName("#define BPF_JMP 0x05")]
    public const int BPF_JMP = 0x05;

    [NativeTypeName("#define BPF_RET 0x06")]
    public const int BPF_RET = 0x06;

    [NativeTypeName("#define BPF_MISC 0x07")]
    public const int BPF_MISC = 0x07;

    [NativeTypeName("#define BPF_W 0x00")]
    public const int BPF_W = 0x00;

    [NativeTypeName("#define BPF_H 0x08")]
    public const int BPF_H = 0x08;

    [NativeTypeName("#define BPF_B 0x10")]
    public const int BPF_B = 0x10;

    [NativeTypeName("#define BPF_IMM 0x00")]
    public const int BPF_IMM = 0x00;

    [NativeTypeName("#define BPF_ABS 0x20")]
    public const int BPF_ABS = 0x20;

    [NativeTypeName("#define BPF_IND 0x40")]
    public const int BPF_IND = 0x40;

    [NativeTypeName("#define BPF_MEM 0x60")]
    public const int BPF_MEM = 0x60;

    [NativeTypeName("#define BPF_LEN 0x80")]
    public const int BPF_LEN = 0x80;

    [NativeTypeName("#define BPF_MSH 0xa0")]
    public const int BPF_MSH = 0xa0;

    [NativeTypeName("#define BPF_ADD 0x00")]
    public const int BPF_ADD = 0x00;

    [NativeTypeName("#define BPF_SUB 0x10")]
    public const int BPF_SUB = 0x10;

    [NativeTypeName("#define BPF_MUL 0x20")]
    public const int BPF_MUL = 0x20;

    [NativeTypeName("#define BPF_DIV 0x30")]
    public const int BPF_DIV = 0x30;

    [NativeTypeName("#define BPF_OR 0x40")]
    public const int BPF_OR = 0x40;

    [NativeTypeName("#define BPF_AND 0x50")]
    public const int BPF_AND = 0x50;

    [NativeTypeName("#define BPF_LSH 0x60")]
    public const int BPF_LSH = 0x60;

    [NativeTypeName("#define BPF_RSH 0x70")]
    public const int BPF_RSH = 0x70;

    [NativeTypeName("#define BPF_NEG 0x80")]
    public const int BPF_NEG = 0x80;

    [NativeTypeName("#define BPF_MOD 0x90")]
    public const int BPF_MOD = 0x90;

    [NativeTypeName("#define BPF_XOR 0xa0")]
    public const int BPF_XOR = 0xa0;

    [NativeTypeName("#define BPF_JA 0x00")]
    public const int BPF_JA = 0x00;

    [NativeTypeName("#define BPF_JEQ 0x10")]
    public const int BPF_JEQ = 0x10;

    [NativeTypeName("#define BPF_JGT 0x20")]
    public const int BPF_JGT = 0x20;

    [NativeTypeName("#define BPF_JGE 0x30")]
    public const int BPF_JGE = 0x30;

    [NativeTypeName("#define BPF_JSET 0x40")]
    public const int BPF_JSET = 0x40;

    [NativeTypeName("#define BPF_K 0x00")]
    public const int BPF_K = 0x00;

    [NativeTypeName("#define BPF_X 0x08")]
    public const int BPF_X = 0x08;

    [NativeTypeName("#define BPF_A 0x10")]
    public const int BPF_A = 0x10;

    [NativeTypeName("#define BPF_TAX 0x00")]
    public const int BPF_TAX = 0x00;

    [NativeTypeName("#define BPF_TXA 0x80")]
    public const int BPF_TXA = 0x80;

    [NativeTypeName("#define BPF_MEMWORDS 16")]
    public const int BPF_MEMWORDS = 16;

    [NativeTypeName("#define PCAP_VERSION_MAJOR 2")]
    public const int PCAP_VERSION_MAJOR = 2;

    [NativeTypeName("#define PCAP_VERSION_MINOR 4")]
    public const int PCAP_VERSION_MINOR = 4;

    [NativeTypeName("#define PCAP_ERRBUF_SIZE 256")]
    public const int PCAP_ERRBUF_SIZE = 256;

    [NativeTypeName("#define PCAP_IF_LOOPBACK 0x00000001")]
    public const int PCAP_IF_LOOPBACK = 0x00000001;

    [NativeTypeName("#define PCAP_IF_UP 0x00000002")]
    public const int PCAP_IF_UP = 0x00000002;

    [NativeTypeName("#define PCAP_IF_RUNNING 0x00000004")]
    public const int PCAP_IF_RUNNING = 0x00000004;

    [NativeTypeName("#define PCAP_IF_WIRELESS 0x00000008")]
    public const int PCAP_IF_WIRELESS = 0x00000008;

    [NativeTypeName("#define PCAP_IF_CONNECTION_STATUS 0x00000030")]
    public const int PCAP_IF_CONNECTION_STATUS = 0x00000030;

    [NativeTypeName("#define PCAP_IF_CONNECTION_STATUS_UNKNOWN 0x00000000")]
    public const int PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000;

    [NativeTypeName("#define PCAP_IF_CONNECTION_STATUS_CONNECTED 0x00000010")]
    public const int PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010;

    [NativeTypeName("#define PCAP_IF_CONNECTION_STATUS_DISCONNECTED 0x00000020")]
    public const int PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020;

    [NativeTypeName("#define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE 0x00000030")]
    public const int PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030;

    [NativeTypeName("#define PCAP_ERROR -1")]
    public const int PCAP_ERROR = -1;

    [NativeTypeName("#define PCAP_ERROR_BREAK -2")]
    public const int PCAP_ERROR_BREAK = -2;

    [NativeTypeName("#define PCAP_ERROR_NOT_ACTIVATED -3")]
    public const int PCAP_ERROR_NOT_ACTIVATED = -3;

    [NativeTypeName("#define PCAP_ERROR_ACTIVATED -4")]
    public const int PCAP_ERROR_ACTIVATED = -4;

    [NativeTypeName("#define PCAP_ERROR_NO_SUCH_DEVICE -5")]
    public const int PCAP_ERROR_NO_SUCH_DEVICE = -5;

    [NativeTypeName("#define PCAP_ERROR_RFMON_NOTSUP -6")]
    public const int PCAP_ERROR_RFMON_NOTSUP = -6;

    [NativeTypeName("#define PCAP_ERROR_NOT_RFMON -7")]
    public const int PCAP_ERROR_NOT_RFMON = -7;

    [NativeTypeName("#define PCAP_ERROR_PERM_DENIED -8")]
    public const int PCAP_ERROR_PERM_DENIED = -8;

    [NativeTypeName("#define PCAP_ERROR_IFACE_NOT_UP -9")]
    public const int PCAP_ERROR_IFACE_NOT_UP = -9;

    [NativeTypeName("#define PCAP_ERROR_CANTSET_TSTAMP_TYPE -10")]
    public const int PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10;

    [NativeTypeName("#define PCAP_ERROR_PROMISC_PERM_DENIED -11")]
    public const int PCAP_ERROR_PROMISC_PERM_DENIED = -11;

    [NativeTypeName("#define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP -12")]
    public const int PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12;

    [NativeTypeName("#define PCAP_WARNING 1")]
    public const int PCAP_WARNING = 1;

    [NativeTypeName("#define PCAP_WARNING_PROMISC_NOTSUP 2")]
    public const int PCAP_WARNING_PROMISC_NOTSUP = 2;

    [NativeTypeName("#define PCAP_WARNING_TSTAMP_TYPE_NOTSUP 3")]
    public const int PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3;

    [NativeTypeName("#define PCAP_NETMASK_UNKNOWN 0xffffffff")]
    public const uint PCAP_NETMASK_UNKNOWN = 0xffffffff;

    [NativeTypeName("#define PCAP_CHAR_ENC_LOCAL 0x00000000U")]
    public const uint PCAP_CHAR_ENC_LOCAL = 0x00000000U;

    [NativeTypeName("#define PCAP_CHAR_ENC_UTF_8 0x00000001U")]
    public const uint PCAP_CHAR_ENC_UTF_8 = 0x00000001U;

    [NativeTypeName("#define PCAP_TSTAMP_HOST 0")]
    public const int PCAP_TSTAMP_HOST = 0;

    [NativeTypeName("#define PCAP_TSTAMP_HOST_LOWPREC 1")]
    public const int PCAP_TSTAMP_HOST_LOWPREC = 1;

    [NativeTypeName("#define PCAP_TSTAMP_HOST_HIPREC 2")]
    public const int PCAP_TSTAMP_HOST_HIPREC = 2;

    [NativeTypeName("#define PCAP_TSTAMP_ADAPTER 3")]
    public const int PCAP_TSTAMP_ADAPTER = 3;

    [NativeTypeName("#define PCAP_TSTAMP_ADAPTER_UNSYNCED 4")]
    public const int PCAP_TSTAMP_ADAPTER_UNSYNCED = 4;

    [NativeTypeName("#define PCAP_TSTAMP_HOST_HIPREC_UNSYNCED 5")]
    public const int PCAP_TSTAMP_HOST_HIPREC_UNSYNCED = 5;

    [NativeTypeName("#define PCAP_TSTAMP_PRECISION_MICRO 0")]
    public const int PCAP_TSTAMP_PRECISION_MICRO = 0;

    [NativeTypeName("#define PCAP_TSTAMP_PRECISION_NANO 1")]
    public const int PCAP_TSTAMP_PRECISION_NANO = 1;

    [NativeTypeName("#define MODE_CAPT 0")]
    public const int MODE_CAPT = 0;

    [NativeTypeName("#define MODE_STAT 1")]
    public const int MODE_STAT = 1;

    [NativeTypeName("#define MODE_MON 2")]
    public const int MODE_MON = 2;

    [NativeTypeName("#define PCAP_BUF_SIZE 1024")]
    public const int PCAP_BUF_SIZE = 1024;

    [NativeTypeName("#define PCAP_SRC_FILE 2")]
    public const int PCAP_SRC_FILE = 2;

    [NativeTypeName("#define PCAP_SRC_IFLOCAL 3")]
    public const int PCAP_SRC_IFLOCAL = 3;

    [NativeTypeName("#define PCAP_SRC_IFREMOTE 4")]
    public const int PCAP_SRC_IFREMOTE = 4;

    [NativeTypeName("#define PCAP_SRC_FILE_STRING \"file://\"")]
    public static ReadOnlySpan<byte> PCAP_SRC_FILE_STRING => "file://"u8;

    [NativeTypeName("#define PCAP_SRC_IF_STRING \"rpcap://\"")]
    public static ReadOnlySpan<byte> PCAP_SRC_IF_STRING => "rpcap://"u8;

    [NativeTypeName("#define PCAP_OPENFLAG_PROMISCUOUS 0x00000001")]
    public const int PCAP_OPENFLAG_PROMISCUOUS = 0x00000001;

    [NativeTypeName("#define PCAP_OPENFLAG_DATATX_UDP 0x00000002")]
    public const int PCAP_OPENFLAG_DATATX_UDP = 0x00000002;

    [NativeTypeName("#define PCAP_OPENFLAG_NOCAPTURE_RPCAP 0x00000004")]
    public const int PCAP_OPENFLAG_NOCAPTURE_RPCAP = 0x00000004;

    [NativeTypeName("#define PCAP_OPENFLAG_NOCAPTURE_LOCAL 0x00000008")]
    public const int PCAP_OPENFLAG_NOCAPTURE_LOCAL = 0x00000008;

    [NativeTypeName("#define PCAP_OPENFLAG_MAX_RESPONSIVENESS 0x00000010")]
    public const int PCAP_OPENFLAG_MAX_RESPONSIVENESS = 0x00000010;

    [NativeTypeName("#define RPCAP_RMTAUTH_NULL 0")]
    public const int RPCAP_RMTAUTH_NULL = 0;

    [NativeTypeName("#define RPCAP_RMTAUTH_PWD 1")]
    public const int RPCAP_RMTAUTH_PWD = 1;

    [NativeTypeName("#define PCAP_SAMP_NOSAMP 0")]
    public const int PCAP_SAMP_NOSAMP = 0;

    [NativeTypeName("#define PCAP_SAMP_1_EVERY_N 1")]
    public const int PCAP_SAMP_1_EVERY_N = 1;

    [NativeTypeName("#define PCAP_SAMP_FIRST_AFTER_N_MS 2")]
    public const int PCAP_SAMP_FIRST_AFTER_N_MS = 2;

    [NativeTypeName("#define RPCAP_HOSTLIST_SIZE 1024")]
    public const int RPCAP_HOSTLIST_SIZE = 1024;
}
