using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UdemyAuthServer.Core.UnitOfWork
{
    public interface IUnitOFWork
    {
        Task SaveChangesAsync();
        void SaveChanges();
    }
}
