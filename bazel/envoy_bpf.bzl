"""The build rules for eBPF programs and skeleton headers."""

load(":envoy_internal.bzl", "envoy_external_dep_path")

def bpf_program(name, src, bpf_object, hdrs=[], **kwargs):
    """Generates an eBPF object file from .c source code.

    Args:
      name: target name for eBPF program.
      src: eBPF program source code in C.
      hdrs: list of header files depended on by src.
      bpf_object: name of generated eBPF object file.
      **kwargs: additional arguments.
    """
    #deps = deps + [envoy_external_dep_path(dep) for dep in external_deps]

    native.genrule(
        name = name,
        srcs = [envoy_external_dep_path("libbpf")] + [src] + hdrs,
        outs = [bpf_object],
        cmd = (
            "clang -Wall -g -O2 -mcpu=v3 -target bpf -D__TARGET_ARCH_x86 " +
            # The `.` directory is the project root, so we pass it with the `-I`
            # flag so that #includes work in the source files.
            #
            # `$@` is the location to write the eBPF object file.
            "-I . -I $(BINDIR)/external/envoy/bazel/foreign_cc/libbpf/include -c $(location " + src + ") -o $@ && " +
            "llvm-strip -g $@"
        ),
        **kwargs
    )

def bpf_skeleton(name, bpf_object, skel_hdr, **kwargs):
    """Generates eBPF skeleton from object file to .h skeleton source code.

    Args:
      name: target name for eBPF program.
      bpf_object: built eBPF program.
      skel_hdr: name of generated skeleton header file.
      **kwargs: additional arguments.
    """
    
    bpftool_label = envoy_external_dep_path("bpftool")

    native.genrule(
        name = name,
        srcs = [bpf_object],
        outs = [skel_hdr],
        tools = [bpftool_label],
        cmd = (
            "BPFTOOL=$$(echo $(locations " + bpftool_label + ") | grep -oE \"[^[:space:]]*/bin/bpftool[[:space:]]*\") && " +
            "$$BPFTOOL gen skeleton $(location " + bpf_object + ") > $@"
        ),
        **kwargs
    )