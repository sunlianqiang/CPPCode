struct new_ptr_list_t
{
	/* data */
	new_ptr_list_t* next;
	char fn[DEBUG_NEW_FILENAME_SIZE];
	int line;
	size_t size;
	new_ptr_list_t()
	{
		next = NULL;
		bzero(fn, DEBUG_NEW_FILENAME_SIZE);
		line = 0;
		size = 0;
	}
};

static new_ptr_list_t* new_ptr_list[DEBUG_NEW_FILENAME_SIZE];

void* operator new(size_t size, const char* file, int line)
{
    size_t s = size + sizeof(new_ptr_list_t);
    new_ptr_list_t* ptr = (new_ptr_list_t*)malloc(s);
    if (ptr == NULL)
    {
    	abort();
    }

    void* p = (char*)ptr + sizeof(new_ptr_list_t);

    size_t hash_index = DEBUG_NEW_HASH(p);
    strncpy(ptr->fn, file, DEBUG_NEW_FILENAME_SIZE -1 );
    ptr->line = line;
    ptr->size = size;

    mem_mutex.lock();
    ptr->next = new_ptr_list_t[hash_index];
    new_ptr_list_t[hash_index] = ptr;
    ++list_size;
    mem_mutex.unlock();

    if (file && line)
    	fprintf(stdout, "内存分配： %p(size %u, %s:%d)\n", p, ptr->size, ptr->fn, ptr->line);

    return p;
}

#define FIR_NEW new
//new对象时打印所在文件、行
#define FIR_NEW new(__FILE__, __LINE__)


void operator delete(void* pointer)
{
	if (pointer == NULL)
		return;

	size_t hash_index = DEBUG_NEW_HASH(pointer);
	new_ptr_list_t* ptr_pre = NULL;

	mem_mutex.lock();
	new_ptr_list_t* ptr = new_ptr_list_t[hash_index];
	while (ptr)
	{
		if ((char*)ptr + sizeof(new_ptr_list_t) == pointer)
		{
			if (ptr->fn && ptr->line)
				fprintf(stdout, "内存释放：%p(size %u)\n", pointer, ptr->size);

			if (ptr_pre == NULL)
				new_ptr_list_t[hash_index] = ptr->next;
			else
				ptr_pre->next = ptr->next;

			--list_size;
			mem_mutex.unlock();
			free(ptr);
			return;
		}

		ptr_pre = ptr;
		ptr = ptr->next;
	}

	mem_mutex.unlock();
	free(pointer);

	if (Fir::logger)
	{
		Fir::logger->trace("[内存释放]: 无效地址 %p", pointer);
		abort();	
	}	

}


bool check_leaks()
{
	struct ListEntry
	{
		/* data */
		char name[DEBUG_NEW_FILENAME_SIZE + 8];
		int size;
	};

	bool fLeaked = false;
	size_t index = 0;
	ListEntry* tempList = NULL;

	mem_mutex.lock();
	tempList = (ListEntry*)malloc(sizeof(ListEntry) * list_size);
	if(!tempList)
	{
		mem_mutex.unlock();
		return false;
	}

	for (int i = 0; i < DEBUG_NEW_FILENAME_SIZE; ++i)
	{
		new_ptr_list* ptr = new_ptr_list[i];
		if (ptr == NULL)
			continue;
		fLeaked = true;
		while (ptr)
		{
			if (Fir::logger)
				Fir::logger->trace("[内存泄露]: %p (size %u, %s:%d)", (char*)ptr + sizeof(new_ptr_list), ptr->size, ptr->fn, ptr->line);
			if (index < list_size)
			{
				snprintf(tempList[index].name, DEBUG_NEW_FILENAME_SIZE + 8, "%s:%d", ptr->fn, ptr->line);
				tempList[index].size = ptr->size;
				++index;
			}

			ptr = ptr->next;
		}
	}
	mem_mutex.unlock();

	std::map<std::string, int> leak_count;
	for (size_t i = 0; i < index; ++i)
		leak_count[tempList[i].name] += tempList[i].size;
	free(tempList);

	for (std::map<std::string>, int>::iterator it = leak_count.begin(); it != leak_count.end(); ++it)
	{
		Fir::logger->trace("[内存泄露分类统计]: %s size:%d", it->first.c_str(), it->second);
	}

	mutex.lock();
	for (std::unordered_map<QWORD, NewAddr>::iterator iter = newAddrMap.begin(); iter != newAddrMap.end(); ++iter)
	{
		fLeaked = true;
		Fir::logger->trace("[内存泄露分类统计]: %s:%u size:%lu", iter->second.file, iter->second.line, iter->second.size);
	}
	mutex.unlock();

	if (!fLeaked)
	{
		Fir::logger->trace("[内存泄露]: 该程序没有任何内存泄露");
	}

	return fLeaked;
}
