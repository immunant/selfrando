find_original() {
    local WRAPPER=`basename $0`
    local AFTER_WRAPPER=false

    IFS=: read -ra PATHVAR <<< "$PATH";
    for PATHELEM in "${PATHVAR[@]}"; do
        ORIG_BINARY="$PATHELEM/$WRAPPER"
        if [[ "$ORIG_BINARY" -ef "$0" ]]; then
            AFTER_WRAPPER=true
        elif $AFTER_WRAPPER && [[ -x "$ORIG_BINARY" ]]; then
            echo "$ORIG_BINARY"
            break
        fi
    done

}

run_original() {
    ORIG_BINARY=`find_original`
    exec "$ORIG_BINARY" "$@"
}
