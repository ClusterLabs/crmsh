# bash completion for crm(8)
shopt -s extglob
_crm() {
    local cur prev cmd cmd_index
    COMPREPLY=()
    cur="$2"
    prev="$3"

    for ((i=1; $i<=$COMP_CWORD; i++)); do
        if [[ ${COMP_WORDS[i]} != -* ]]; then
            if [[ ${COMP_WORDS[i-1]} != @(-f|--file|-H|--history|-D|--display|-X|-c|--cib) ]]; then
                arg="${COMP_WORDS[i]}"
                argi=$i
                break
            fi
        fi
    done

    case $prev in
        -f|--file|-H|--history|-D|--display|-X|-c|--cib)
            # use default completion
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=(${COMPREPLY[@]:-} $(compgen -W '-w -h -d -F -R -f --file -H --history -D --display -X -c --cib' -- "$cur"))
        return 0
    fi

    COMPREPLY=(${COMPREPLY[@]:-} $(compgen -W '$(2>/dev/null ./crm --compgen "${COMP_POINT}" "${COMP_LINE}")' -- "$cur"))
} &&
complete -o bashdefault -o default -F _crm crm     || complete -o default -F _crm crm
