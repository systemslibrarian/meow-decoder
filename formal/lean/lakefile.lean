import Lake
open Lake DSL

package «meow_formal» where
  -- Package configuration
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.5.0"

@[default_target]
lean_lib «FountainCodes» where
  globs := #[.one `FountainCodes]
  moreLinkArgs := #[]

/-- Check all proofs -/
lean_exe «check» where
  root := `FountainCodes
