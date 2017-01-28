
// From http://graphics.stanford.edu/~seander/bithacks.html#FixedSignExtend
// In the public domain
template <typename T, unsigned B>
inline T signextend(const T x) {
    struct {T x:B;} s;
    return s.x = x;
}
