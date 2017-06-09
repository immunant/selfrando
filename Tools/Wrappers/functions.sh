find_original() {
    local wrapper=`basename $0`
    local after_wrapper=false
    local pathvar
    local orig_path

    IFS=: read -ra pathvar <<< "$PATH";
    for orig_path in "${pathvar[@]}"; do
        local orig_binary="$orig_path/$wrapper"
        if [[ "$orig_binary" -ef "$0" ]]; then
            after_wrapper=true
        elif $after_wrapper && [[ -x "$orig_binary" ]]; then
            echo "$orig_binary"
            break
        fi
    done

}

run_original() {
    local orig_binary=`find_original`
    exec "$orig_binary" "$@"
}

exec_traplinker() {
    local traplinker=$1
    shift

    if [[ ! -x "$traplinker" ]]; then
        echo "TrapLinker not found at: '$traplinker'; please build selfrando." 1>&2
        exit 1
    fi
    exec "$traplinker" "$@"
}
