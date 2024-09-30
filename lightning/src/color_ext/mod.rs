use std::path::PathBuf;

/// RGB Lightning Node color extension trait
pub trait ColorSource {
	/// just for migration from legacy code
	fn get_ldk_data_dir(&self) -> PathBuf;
}
