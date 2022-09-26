$clangsharp = "D:\projects\ClangSharp\artifacts\bin\sources\ClangSharpPInvokeGenerator\Debug\net7.0\ClangSharpPInvokeGenerator.exe"

# libpcap
Write-Host "Generating libpcap bindings.."
& $clangsharp `
    --file-directory ./libs/libpcap-1.10.1 `
    --file pcap.h `
    --include-directory ./libs/libpcap-1.10.1 `
    --traverse ./libs/libpcap-1.10.1/pcap.h `
    --traverse ./libs/libpcap-1.10.1/pcap/dlt.h `
    --traverse ./libs/libpcap-1.10.1/pcap/pcap.h `
    --traverse ./libs/libpcap-1.10.1/pcap/bpf.h `
    --output ./src/Libpcap/Native `
    --namespace Libpcap.Native `
    --methodClassName LibpcapNative `
    --libraryPath pcap `
    --with-access-specifier *=internal `
    --config preview-codegen generate-file-scoped-namespaces generate-macro-bindings multi-file `
    --exclude BPF_WORDALIGN BPF_CLASS BPF_SIZE BPF_MODE BPF_OP BPF_SRC BPF_RVAL BPF_MISCOP BPF_STMT BPF_JUMP `
    --exclude LT_FCS_LENGTH_PRESENT LT_FCS_LENGTH LT_FCS_DATALINK_EXT pcap_fopen_offline_with_tstamp_precision pcap_fopen_offline pcap_dump_fopen `
    --exclude DLT_CLASS DLT_NETBSD_RAWAF DLT_NETBSD_RAWAF_AF DLT_IS_NETBSD_RAWAF
