// Copyright 2023 Divy Srivastava <dj.srivastava23@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[inline]
fn unmask_easy(payload: &mut [u8], mask: [u8; 4]) {
  payload.iter_mut().enumerate().for_each(|(i, v)| {
    *v ^= mask[i & 3];
  });
}

// TODO(@littledivy): Compiler does a good job at auto-vectorizing `unmask_fallback` with
// -C target-cpu=native. Below is a manual implementation.
//
// #[cfg(all(target_arch = "x86_64", feature = "simd"))]
// #[inline]
// fn unmask_x86_64(payload: &mut [u8], mask: [u8; 4]) {
//   #[inline]
//   fn sse2(payload: &mut [u8], mask: [u8; 4]) {
//     const ALIGNMENT: usize = 16;
//     unsafe {
//       use std::arch::x86_64::*;
//
//       let len = payload.len();
//       if len < ALIGNMENT {
//         return unmask_fallback(payload, mask);
//       }
//
//       let start = len - len % ALIGNMENT;
//
//       let mut aligned_mask = [0; ALIGNMENT];
//
//       for j in (0..ALIGNMENT).step_by(4) {
//         aligned_mask[j] = mask[j % 4];
//         aligned_mask[j + 1] = mask[(j % 4) + 1];
//         aligned_mask[j + 2] = mask[(j % 4) + 2];
//         aligned_mask[j + 3] = mask[(j % 4) + 3];
//       }
//
//       let mask_m = _mm_loadu_si128(aligned_mask.as_ptr() as *const _);
//
//       for index in (0..start).step_by(ALIGNMENT) {
//         let ptr = payload.as_mut_ptr().add(index);
//         let mut v = _mm_loadu_si128(ptr as *const _);
//         v = _mm_xor_si128(v, mask_m);
//         _mm_storeu_si128(ptr as *mut _, v);
//       }
//
//       if len != start {
//         unmask_fallback(&mut payload[start..], mask);
//       }
//     }
//   }
//   #[cfg(target_feature = "sse2")]
//   {
//     return sse2(payload, mask);
//   }
//
//   #[cfg(not(target_feature = "sse2"))]
//   {
//     use core::mem;
//     use std::sync::atomic::AtomicPtr;
//     use std::sync::atomic::Ordering;
//
//     type FnRaw = *mut ();
//     type FnImpl = unsafe fn(&mut [u8], [u8; 4]);
//
//     unsafe fn get_impl(input: &mut [u8], mask: [u8; 4]) {
//       let fun = if std::is_x86_feature_detected!("sse2") {
//         sse2
//       } else {
//         unmask_fallback
//       };
//       FN.store(fun as FnRaw, Ordering::Relaxed);
//       (fun)(input, mask);
//     }
//
//     static FN: AtomicPtr<()> = AtomicPtr::new(get_impl as FnRaw);
//
//     if payload.len() < 16 {
//       return unmask_fallback(payload, mask);
//     }
//
//     let fun = FN.load(Ordering::Relaxed);
//     unsafe { mem::transmute::<FnRaw, FnImpl>(fun)(payload, mask) }
//   }
// }

// Faster version of `unmask_easy()` which operates on 4-byte blocks.
// https://github.com/snapview/tungstenite-rs/blob/e5efe537b87a6705467043fe44bb220ddf7c1ce8/src/protocol/frame/mask.rs#L23
//
// https://godbolt.org/z/EPTYo5jK8
#[inline]
fn unmask_fallback(buf: &mut [u8], mask: [u8; 4]) {
  let mask_u32 = u32::from_ne_bytes(mask);

  let (prefix, words, suffix) = unsafe { buf.align_to_mut::<u32>() };
  unmask_easy(prefix, mask);
  let head = prefix.len() & 3;
  let mask_u32 = if head > 0 {
    if cfg!(target_endian = "big") {
      mask_u32.rotate_left(8 * head as u32)
    } else {
      mask_u32.rotate_right(8 * head as u32)
    }
  } else {
    mask_u32
  };
  for word in words.iter_mut() {
    *word ^= mask_u32;
  }
  unmask_easy(suffix, mask_u32.to_ne_bytes());
}

/// AVX2 unmask — processes 32 bytes at a time (2x SSE2 throughput).
/// i7-9750H (Coffee Lake) supports AVX2 with no frequency penalty.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn unmask_avx2(payload: &mut [u8], mask: [u8; 4]) {
  use std::arch::x86_64::*;
  const BLOCK: usize = 32;
  let len = payload.len();

  // Single-instruction broadcast: vpbroadcastd (1 cycle, no stack array)
  let mask_v = _mm256_set1_epi32(i32::from_ne_bytes(mask));

  let aligned_end = len - (len % BLOCK);
  let mut i = 0;
  while i < aligned_end {
    let ptr = payload.as_mut_ptr().add(i);
    let data = _mm256_loadu_si256(ptr as *const _);
    let result = _mm256_xor_si256(data, mask_v);
    _mm256_storeu_si256(ptr as *mut _, result);
    i += BLOCK;
  }

  // Handle remaining bytes (< 32) with SSE2
  if aligned_end < len {
    unmask_sse2(&mut payload[aligned_end..], mask);
  }
}

/// SSE2 unmask — processes 16 bytes at a time. Fallback for small tails.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn unmask_sse2(payload: &mut [u8], mask: [u8; 4]) {
  use std::arch::x86_64::*;
  const BLOCK: usize = 16;
  let len = payload.len();
  if len < BLOCK {
    return unmask_fallback(payload, mask);
  }

  // Single-instruction broadcast: pshufd (1 cycle, no stack array)
  let mask_v = _mm_set1_epi32(i32::from_ne_bytes(mask));

  let aligned_end = len - (len % BLOCK);
  let mut i = 0;
  while i < aligned_end {
    let ptr = payload.as_mut_ptr().add(i);
    let data = _mm_loadu_si128(ptr as *const _);
    let result = _mm_xor_si128(data, mask_v);
    _mm_storeu_si128(ptr as *mut _, result);
    i += BLOCK;
  }

  if aligned_end < len {
    unmask_fallback(&mut payload[aligned_end..], mask);
  }
}

/// Unmask a payload using the given 4-byte mask.
/// Uses AVX2 (32B/cycle) when available, SSE2 (16B/cycle) fallback.
#[inline]
pub fn unmask(payload: &mut [u8], mask: [u8; 4]) {
  #[cfg(target_arch = "x86_64")]
  {
    let len = payload.len();
    // AVX2 for large payloads (32+ bytes), SSE2 for medium, scalar for tiny
    if len >= 32 {
      // Compile-time AVX2 gate: target-cpu=native enables this on i7-9750H.
      // Eliminates per-frame runtime is_x86_feature_detected! atomic load.
      #[cfg(target_feature = "avx2")]
      {
        unsafe { unmask_avx2(payload, mask) };
        return;
      }
      #[cfg(not(target_feature = "avx2"))]
      if is_x86_feature_detected!("avx2") {
        unsafe { unmask_avx2(payload, mask) };
        return;
      }
    }
    if len >= 16 {
      unsafe { unmask_sse2(payload, mask) };
      return;
    }
    unmask_fallback(payload, mask);
    return;
  }
  #[cfg(not(target_arch = "x86_64"))]
  {
    unmask_fallback(payload, mask);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_unmask() {
    let mut payload = [0u8; 33];
    let mask = [1, 2, 3, 4];
    unmask(&mut payload, mask);
    assert_eq!(
      &payload,
      &[
        1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
        1, 2, 3, 4, 1, 2, 3, 4, 1
      ]
    );
  }

  #[test]
  fn length_variation_unmask() {
    for len in &[0, 2, 3, 8, 16, 18, 31, 32, 40] {
      let mut payload = vec![0u8; *len];
      let mask = [1, 2, 3, 4];
      unmask(&mut payload, mask);

      let expected = (0..*len).map(|i| (i & 3) as u8 + 1).collect::<Vec<_>>();
      assert_eq!(payload, expected);
    }
  }

  #[test]
  fn length_variation_unmask_2() {
    for len in &[0, 2, 3, 8, 16, 18, 31, 32, 40] {
      let mut payload = vec![0u8; *len];
      let mask = rand::random::<[u8; 4]>();
      unmask(&mut payload, mask);

      let expected = (0..*len).map(|i| mask[i & 3]).collect::<Vec<_>>();
      assert_eq!(payload, expected);
    }
  }
}
