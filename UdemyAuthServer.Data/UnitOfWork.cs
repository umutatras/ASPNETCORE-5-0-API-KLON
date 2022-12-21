using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UdemyAuthServer.Core.UnitOfWork;

namespace UdemyAuthServer.Data
{
    public class UnitOfWork : IUnitOFWork
    {
        private readonly DbContext _context;
        public UnitOfWork(AppDbContext appDbContext)
        {
            _context= appDbContext;
        }
        public void SaveChanges()
        {
            _context.SaveChanges();
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();    
        }
    }
}
