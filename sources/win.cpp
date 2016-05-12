#ifdef _WIN32
#include "platform.h"

namespace securefs {
	class FileSystemService::Impl
	{
	public:
		std::string dir_name;
		int dir_fd;
	};

	FileSystemService::FileSystemService() : impl(new Impl())
	{
		
	}

	FileSystemService::~FileSystemService()
	{
		
	}

	FileSystemService::FileSystemService(const std::string& path) : impl(new Impl())
	{
		
	}

	std::shared_ptr<FileStream>
		FileSystemService::open_file_stream(const std::string& path, int flags, unsigned mode)
	{
		return nullptr;
	}

	bool FileSystemService::remove_file(const std::string& path) noexcept
	{
		return false;
	}

	bool FileSystemService::remove_directory(const std::string& path) noexcept
	{
		return false;
	}

	void FileSystemService::lock()
	{
	}

	void FileSystemService::ensure_directory(const std::string& path, unsigned mode)
	{
		
	}

	void FileSystemService::statfs(struct statvfs* fs_info)
	{
		
	}

	void FileSystemService::rename(const std::string& a, const std::string& b)
	{
		int rc = ::rename(a.c_str(), b.c_str());
		if (rc < 0)
			throw UnderlyingOSException(
				errno,
				fmt::format("Renaming from {}/{} to {}/{}", impl->dir_name, a, impl->dir_name, b));
	}

	uint32_t FileSystemService::getuid() noexcept { return 0; }
	uint32_t FileSystemService::getgid() noexcept { return 0; }

	bool FileSystemService::raise_fd_limit() noexcept
	{
		return false;
	}
}
#endif