;; Inazuma example contract: a counter with a greeting.
;;
;;   args ""        -> increment the counter by 1
;;   args "get"     -> return the counter without changing it
;;   args "add:<n>" -> add n (n is a single ascii digit for brevity)
;;
;; Storage layout: key "count" holds the decimal count as ascii.
(module
  (import "env" "inz_input_len" (func $input_len (result i32)))
  (import "env" "inz_input" (func $input (param i32 i32) (result i32)))
  (import "env" "inz_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "env" "inz_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "env" "inz_return" (func $ret (param i32 i32)))
  (import "env" "inz_log" (func $log (param i32 i32)))
  (memory (export "memory") 1)

  ;; 0..15   key "count"
  ;; 16..47  value scratch (ascii number)
  ;; 48..79  input scratch
  ;; 80..111 log scratch
  (data (i32.const 0) "count")
  (data (i32.const 80) "counter bumped")

  (global $val (mut i64) (i64.const 0))

  ;; parse ascii decimal at 16 with length $len into an i64
  (func $parse (param $len i32) (result i64)
    (local $i i32) (local $acc i64)
    (local.set $i (i32.const 0))
    (local.set $acc (i64.const 0))
    (block $done
      (loop $next
        (br_if $done (i32.ge_s (local.get $i) (local.get $len)))
        (local.set $acc
          (i64.add
            (i64.mul (local.get $acc) (i64.const 10))
            (i64.extend_i32_u
              (i32.sub (i32.load8_u (i32.add (i32.const 16) (local.get $i))) (i32.const 48)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (local.get $acc))

  ;; write $v as ascii decimal at 16, return its length
  (func $format (param $v i64) (result i32)
    (local $len i32) (local $i i32) (local $j i32) (local $tmp i32)
    (local.set $len (i32.const 0))
    (if (i64.eqz (local.get $v))
      (then
        (i32.store8 (i32.const 16) (i32.const 48))
        (return (i32.const 1))))
    ;; digits come out reversed into 16.., then get flipped in place
    (block $done
      (loop $next
        (br_if $done (i64.eqz (local.get $v)))
        (i32.store8
          (i32.add (i32.const 16) (local.get $len))
          (i32.add (i32.const 48)
            (i32.wrap_i64 (i64.rem_u (local.get $v) (i64.const 10)))))
        (local.set $v (i64.div_u (local.get $v) (i64.const 10)))
        (local.set $len (i32.add (local.get $len) (i32.const 1)))
        (br $next)))
    (local.set $i (i32.const 0))
    (local.set $j (i32.sub (local.get $len) (i32.const 1)))
    (block $swapped
      (loop $swap
        (br_if $swapped (i32.ge_s (local.get $i) (local.get $j)))
        (local.set $tmp (i32.load8_u (i32.add (i32.const 16) (local.get $i))))
        (i32.store8 (i32.add (i32.const 16) (local.get $i))
          (i32.load8_u (i32.add (i32.const 16) (local.get $j))))
        (i32.store8 (i32.add (i32.const 16) (local.get $j)) (local.get $tmp))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (local.set $j (i32.sub (local.get $j) (i32.const 1)))
        (br $swap)))
    (local.get $len))

  (func $load
    (local $n i32)
    (local.set $n (call $read (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 32)))
    (if (i32.gt_s (local.get $n) (i32.const 0))
      (then (global.set $val (call $parse (local.get $n))))
      (else (global.set $val (i64.const 0)))))

  (func $store
    (local $n i32)
    (local.set $n (call $format (global.get $val)))
    (drop (call $write (i32.const 0) (i32.const 5) (i32.const 16) (local.get $n))))

  (func $emit
    (local $n i32)
    (local.set $n (call $format (global.get $val)))
    (call $ret (i32.const 16) (local.get $n)))

  (func (export "invoke") (result i32)
    (local $len i32)
    (call $load)
    (local.set $len (call $input_len))
    (if (i32.gt_s (local.get $len) (i32.const 0))
      (then (drop (call $input (i32.const 48) (i32.const 32)))))
    ;; "get" -> read only
    (if (i32.and (i32.eq (local.get $len) (i32.const 3))
                 (i32.eq (i32.load8_u (i32.const 48)) (i32.const 103)))
      (then
        (call $emit)
        (return (i32.const 0))))
    ;; "add:<digit>"
    (if (i32.and (i32.eq (local.get $len) (i32.const 5))
                 (i32.eq (i32.load8_u (i32.const 48)) (i32.const 97)))
      (then
        (global.set $val
          (i64.add (global.get $val)
            (i64.extend_i32_u (i32.sub (i32.load8_u (i32.const 52)) (i32.const 48)))))
        (call $store)
        (call $emit)
        (return (i32.const 0))))
    ;; default: +1
    (global.set $val (i64.add (global.get $val) (i64.const 1)))
    (call $store)
    (call $log (i32.const 80) (i32.const 14))
    (call $emit)
    (i32.const 0))
)
